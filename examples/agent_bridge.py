"""Works with any agent framework capable of calling local Python functions."""
from sis.bridge import ToolBridge
from sis.service import Service

service = Service(':memory:')
try:
    bridge = ToolBridge(service)
    print('Tool definitions:', [d['function']['name'] for d in bridge.tools()])
    # Forward the function name and JSON argument string supplied by your model/provider.
    result = bridge.invoke('sis_predict', '{"namespace":"demo","inputs":{"x":10}}')
    print('No rule -> safe abstention:', result)
finally:
    service.registry.close()
