"""Local simulated active-learning loop.

IMPORTANT: The oracle function is a synthetic toy ground truth, not an LLM prediction.
Real applications must obtain trustworthy labels from their actual environment.
"""
from sis.service import Service


def oracle(case):
    # Fake ground truth from the local task specification: output is always a.
    return case['a']


def main():
    s = Service(':memory:')
    train = [{'inputs': {'a': x, 'b': x}, 'output': x} for x in (1, 2, 3)]
    validation = [{'inputs': {'a': 5, 'b': 6}, 'output': 5},
                  {'inputs': {'a': 13, 'b': -5}, 'output': 13}]
    try:
        for i in range(5):
            result = s.study({'namespace':'toy_oracle','train':train,'validation':validation,
                              'promote':True})
            print('Iteration',i,'status:',result['status'])
            if result['status'] == 'locally_validated':
                prediction = s.predict({'namespace':'toy_oracle','inputs':{'a':99,'b':-2}})
                print('Result from stored rule:',prediction)
                return
            active = s.query({'train':train,'limit':1})
            if not active['queries']:
                print('No new distinguishing questions; cannot claim success')
                return
            case = active['queries'][0]['inputs']
            label = oracle(case)  # ONLY the external oracle can supply a real label.
            train.append({'inputs':case,'output':label})
            print('Labeled externally:',case,'->',label)
    finally:
        s.registry.close()


if __name__ == '__main__':
    main()
