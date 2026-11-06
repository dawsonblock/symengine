"""Optional LoRA SFT runner for evaluator-exported v1.8 synthetic labels.

Safety boundary: validation and dry-run use only the standard library. Only an
explicit execution request imports torch / transformers / peft and loads weights.
The generated adapter is NOT promoted to any SIS registry or model endpoint.
"""
import hashlib
import hmac
import json
import math
import re
from pathlib import Path

from .distillation import FORMAT as EXPORT_FORMAT, INSTRUCTION
from .errors import InvalidInput, RuleRejected
from .validation import canonical, check_inputs, check_scalar, check_task_description, input_schema, namespace_name

HASH = re.compile(r'^[0-9a-f]{64}$')
REQUIRED_CONFIG = {
    'model_id', 'output_dir', 'target_modules', 'epochs', 'learning_rate',
    'lora_rank', 'lora_alpha', 'lora_dropout', 'batch_size', 'grad_accumulation',
    'max_length', 'seed', 'allow_download', 'max_steps'
}


def _check_config(config):
    if not isinstance(config, dict) or set(config) != REQUIRED_CONFIG:
        raise InvalidInput('training config requires exactly the documented fields')
    model = config['model_id']
    if not isinstance(model, str) or not 1 <= len(model) <= 256 or '\x00' in model:
        raise InvalidInput('invalid model_id')
    target = config['target_modules']
    if not isinstance(target, list) or not 1 <= len(target) <= 16 or len(set(target)) != len(target) or any(
        not isinstance(x, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,63}', x) for x in target
    ):
        raise InvalidInput('invalid LoRA target_modules')
    if not isinstance(config['output_dir'], str) or not config['output_dir'] or '\x00' in config['output_dir']:
        raise InvalidInput('invalid output_dir')
    ints = {'epochs': (1, 20), 'lora_rank': (1, 128), 'lora_alpha': (1, 256),
            'batch_size': (1, 16), 'grad_accumulation': (1, 64),
            'max_length': (128, 8192), 'seed': (0, 2**31 - 1), 'max_steps': (1, 20000)}
    for name, (low, high) in ints.items():
        v = config[name]
        if type(v) is not int or not low <= v <= high:
            raise InvalidInput(f'{name} must be an integer between {low} and {high}')
    for name, low, high in (('learning_rate', 1e-7, 1e-2), ('lora_dropout', 0, 0.5)):
        v = config[name]
        if type(v) not in (float, int) or not math.isfinite(v) or not low <= v <= high:
            raise InvalidInput(f'invalid {name}')
    if type(config['allow_download']) is not bool:
        raise InvalidInput('allow_download must be boolean')
    if Path(config['output_dir']).exists():
        raise RuleRejected('output_dir must not exist; overwrite and accidental checkpoint reuse forbidden')
    return dict(config)


def validate_export(jsonl_bytes, manifest, *, hmac_key=None, allow_unverified=False):
    """Return validated rows, digest. Signed manifests require custodian key.

    A naked SHA-256 checksum is not a source-authentication mechanism. No
    training run proceeds from unauthenticated export without explicit opt-in.
    """
    if not isinstance(jsonl_bytes, bytes) or len(jsonl_bytes) > 32 * 1024 * 1024:
        raise InvalidInput('training file must be nonempty bytes <=32 MiB')
    if not isinstance(manifest, dict) or set(manifest) != {
        'format', 'evaluation_id', 'bundle_digest', 'count', 'data_sha256',
        'generator', 'qualification', 'limitations', 'hmac_sha256'
    }:
        raise InvalidInput('expected exactly a v2 signed export manifest')
    if manifest['format'] != EXPORT_FORMAT or manifest['generator'] != 'frozen_symbolic_skill':
        raise InvalidInput('unsupported export provenance')
    if not all(isinstance(manifest.get(x), str) and HASH.fullmatch(manifest[x]) for x in ('data_sha256', 'bundle_digest')):
        raise InvalidInput('invalid export digests')
    if not isinstance(manifest['evaluation_id'], str) or not manifest['evaluation_id']:
        raise InvalidInput('missing evaluation id')
    if not isinstance(manifest['qualification'], str) or not manifest['qualification'].startswith('policy_pass'):
        raise RuleRejected('distillation manifest must state policy_pass')
    if not isinstance(manifest['hmac_sha256'], str) or not HASH.fullmatch(manifest['hmac_sha256']):
        raise InvalidInput('invalid evaluator signature format')
    verified = False
    if hmac_key is not None:
        if not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
            raise InvalidInput('HMAC verification requires 32+ byte custodian key')
        body = {k: v for k, v in manifest.items() if k != 'hmac_sha256'}
        expected = hmac.new(hmac_key, canonical(body).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, manifest['hmac_sha256']):
            raise RuleRejected('export evaluator HMAC verification failed')
        verified = True
    elif not allow_unverified:
        raise RuleRejected('custodian HMAC key required; or opt in to unauthenticated local test data')
    file_hash = hashlib.sha256(jsonl_bytes).hexdigest()
    if not hmac.compare_digest(file_hash, manifest['data_sha256']):
        raise RuleRejected('export JSONL SHA-256 mismatch')
    try:
        text = jsonl_bytes.decode('utf8')
        lines = text.splitlines(keepends=True)
    except UnicodeError as exc:
        raise InvalidInput('invalid UTF-8 JSONL') from exc
    if type(manifest['count']) is not int or not 1 <= manifest['count'] <= 256 or len(lines) != manifest['count']:
        raise InvalidInput('count must match bounded export record count')
    rows, seen, schema, namespace = [], set(), None, None
    for line in lines:
        if not line.endswith('\n'):
            raise InvalidInput('every JSONL record must end in newline')
        try:
            record = json.loads(line)
        except ValueError as exc:
            raise InvalidInput('invalid JSONL row') from exc
        if not isinstance(record, dict) or set(record) != {'messages'} or not isinstance(record['messages'], list):
            raise InvalidInput('invalid training messages')
        msgs = record['messages']
        if len(msgs) != 3 or any(not isinstance(m, dict) or set(m) != {'role', 'content'} for m in msgs):
            raise InvalidInput('messages must be three explicit role-content pairs')
        if [m['role'] for m in msgs] != ['system', 'user', 'assistant'] or msgs[0]['content'] != INSTRUCTION:
            raise InvalidInput('message roles or system instruction do not match approved export')
        try:
            user = json.loads(msgs[1]['content'])
            response = json.loads(msgs[2]['content'])
        except (ValueError, TypeError) as exc:
            raise InvalidInput('invalid structured training input or answer') from exc
        if not isinstance(user, dict) or set(user) != {'namespace', 'task_description', 'inputs'} or not isinstance(response, dict) or set(response) != {'output'}:
            raise InvalidInput('unexpected training schema')
        name = namespace_name(user['namespace'])
        check_task_description(user['task_description'])
        inputs = check_inputs(user['inputs'])
        output = check_scalar(response['output'])
        current_schema = input_schema(inputs)
        if namespace is None: namespace = name
        if schema is None: schema = current_schema
        if name != namespace or current_schema != schema:
            raise InvalidInput('mixed namespaces or input schemas in training data')
        key = canonical(inputs)
        if key in seen:
            raise InvalidInput('duplicate training input')
        seen.add(key)
        if msgs[1]['content'] != canonical(user) or msgs[2]['content'] != canonical(response) or canonical(record) + '\n' != line:
            raise InvalidInput('training rows must match canonical custodian export')
        rows.append(record)
    return rows, {'data_sha256': file_hash, 'count': len(rows), 'namespace': namespace,
                  'input_schema': schema, 'evaluator_hmac_verified': verified,
                  'evaluation_id': manifest['evaluation_id'], 'bundle_digest': manifest['bundle_digest']}


def preflight(data_path, manifest_path, config, *, hmac_key=None, allow_unverified=False):
    conf = _check_config(config)
    data = Path(data_path).read_bytes()
    manifest = json.loads(Path(manifest_path).read_text(encoding='utf8'))
    records, evidence = validate_export(data, manifest, hmac_key=hmac_key, allow_unverified=allow_unverified)
    return conf, records, evidence


def encode_rows(records, tokenizer, max_length):
    """Mask ALL prompt tokens: loss applies only to assistant answer and EOS.

    Fail rather than silently cutting off a label or assuming all tokenizer
    chat templates have the same prefix / boundary semantics.
    """
    encoded = []
    for row in records:
        messages = row['messages']
        prompt = tokenizer.apply_chat_template(messages[:2], tokenize=True, add_generation_prompt=True)
        full = tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=False)
        if not isinstance(prompt, list) or not isinstance(full, list) or not full[:len(prompt)] == prompt:
            raise InvalidInput('tokenizer chat template does not preserve prompt prefix; aborting')
        if len(full) > max_length or not len(full) > len(prompt):
            raise InvalidInput('sequence longer than max_length or contains no target tokens; refusing truncation')
        encoded.append({'input_ids': full, 'labels': [-100] * len(prompt) + full[len(prompt):]})
    return encoded


def train(data_path, manifest_path, config, *, hmac_key=None, allow_unverified=False, execute=False):
    conf, records, provenance = preflight(data_path, manifest_path, config,
                                         hmac_key=hmac_key, allow_unverified=allow_unverified)
    plan = {'status': 'preflight_pass', 'training_started': False, 'model_id': conf['model_id'],
            'output_dir': conf['output_dir'], 'max_steps': conf['max_steps'],
            'config_sha256': hashlib.sha256(canonical(conf).encode()).hexdigest(), **provenance,
            'qualification': 'pseudo-labels only; no independent neural performance claim'}
    if not execute:
        return plan
    # Third-party packages are NOT installed automatically or loaded in dry-run.
    try:
        import torch
        from torch.utils.data import Dataset
        from transformers import AutoTokenizer, AutoModelForCausalLM, Trainer, TrainingArguments
        from peft import LoraConfig, get_peft_model, TaskType
    except ImportError as exc:
        raise InvalidInput('install optional extras: pip install -e .[training]; no weights trained') from exc
    torch.manual_seed(conf['seed'])
    tokenizer = AutoTokenizer.from_pretrained(conf['model_id'], trust_remote_code=False,
                                              local_files_only=not conf['allow_download'])
    model = AutoModelForCausalLM.from_pretrained(conf['model_id'], trust_remote_code=False,
                                                 local_files_only=not conf['allow_download'], use_safetensors=True)
    examples = encode_rows(records, tokenizer, conf['max_length'])
    model.config.use_cache = False
    lora = LoraConfig(r=conf['lora_rank'], lora_alpha=conf['lora_alpha'],
                      lora_dropout=conf['lora_dropout'], target_modules=conf['target_modules'],
                      task_type=TaskType.CAUSAL_LM, bias='none')
    model = get_peft_model(model, lora)
    if not any(p.requires_grad for p in model.parameters()):
        raise InvalidInput('LoRA did not create trainable parameters')
    if tokenizer.pad_token_id is None:
        if tokenizer.eos_token_id is None:
            raise InvalidInput('tokenizer needs a pad or eos token')
        tokenizer.pad_token = tokenizer.eos_token
    pad_id = tokenizer.pad_token_id

    class _Data(Dataset):
        def __len__(self): return len(examples)
        def __getitem__(self, i): return examples[i]

    def collate(items):
        length = max(len(r['input_ids']) for r in items)
        return {
            'input_ids': torch.tensor([r['input_ids'] + [pad_id] * (length-len(r['input_ids'])) for r in items]),
            'attention_mask': torch.tensor([[1] * len(r['input_ids']) + [0] * (length-len(r['input_ids'])) for r in items]),
            'labels': torch.tensor([r['labels'] + [-100] * (length-len(r['labels'])) for r in items])
        }

    out = Path(conf['output_dir'])
    out.mkdir(parents=True, exist_ok=False)
    try:
        args = TrainingArguments(output_dir=str(out / 'training_tmp'),
                                 overwrite_output_dir=False, num_train_epochs=conf['epochs'],
                                 max_steps=conf['max_steps'], per_device_train_batch_size=conf['batch_size'],
                                 gradient_accumulation_steps=conf['grad_accumulation'],
                                 learning_rate=float(conf['learning_rate']),
                                 logging_steps=1, save_strategy='no', report_to='none',
                                 seed=conf['seed'], remove_unused_columns=False,
                                 dataloader_num_workers=0, fp16=False, bf16=False)
        trainer = Trainer(model=model, args=args, train_dataset=_Data(), data_collator=collate)
        outcome = trainer.train()
        adapter_dir = out / 'adapter'
        model.save_pretrained(str(adapter_dir), safe_serialization=True)
        tokenizer.save_pretrained(str(adapter_dir))
        run = {**plan, 'status': 'trained_local_adapter', 'training_started': True,
               'global_step': trainer.state.global_step, 'train_loss': float(outcome.training_loss),
               'adapter_files_sha256': {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest()
                                       for p in sorted(adapter_dir.rglob('*')) if p.is_file()},
               'caveats': 'training loss is not holdout accuracy; run independent evaluation before deployment'}
        (out / 'training_receipt.json').write_text(canonical(run) + '\n', encoding='utf8')
        return run
    except BaseException:
        # Preserve partial files for forensic troubleshooting; never mislabel success.
        (out / 'TRAINING_FAILED').write_text('Incomplete training; do not deploy this directory.\n',encoding='utf8')
        raise
