"""Bridge operations, keyed by the wire method each one answers."""
from operations import inventory, memory, naming
from operations.functions import FUNCTION_OPERATIONS

INVENTORY_HANDLERS = {
    "read_binary_inventory_summary": inventory.read_binary_inventory_summary,
    "inspect_native_load_image": memory.inspect_native_load_image,
    "read_bytes": memory.read_bytes,
    "search_bytes": memory.search_bytes,
    "address_to_file_offset": memory.address_to_file_offset,
    "address_name": naming.address_name,
    "list_documents": inventory.list_documents,
    "list_names": inventory.list_names,
    "list_procedures": inventory.list_procedures,
    "list_segments": inventory.list_segments,
    "list_strings": inventory.list_strings,
    "procedure_address": inventory.procedure_address,
    "resolve_containing_procedure": inventory.resolve_containing_procedure,
    "search_procedures": inventory.search_procedures,
    "search_strings": inventory.search_strings,
    "set_address_name": naming.set_address_name,
    "set_addresses_names": naming.set_addresses_names,
}

FUNCTION_HANDLERS = FUNCTION_OPERATIONS
