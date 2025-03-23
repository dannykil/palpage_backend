from typing import Optional

from google.cloud import discoveryengine
from google.longrunning import operations_pb2

# TODO(developer): Uncomment these variables before running the sample.
# project_id = "gen-lang-client-0274842719"
# location = "global"
# # search_engine_id = "app-unstructured-data_1738996146048" # APP ID
# search_engine_id = "ds-unstructured-data_1738996171866" # DATA STORE ID
project_id = "vertexaisearch-dev"
location = "global"
search_engine_id = "dev-hjk-search-ds-approval_1739162037510" # DATA STORE ID

# Create filter in https://google.aip.dev/160 syntax
# operations_filter = "YOUR_FILTER"
operations_filter = ""


def list_operations_sample(
    project_id: str,
    location: str,
    search_engine_id: str,
    operations_filter: Optional[str] = None,
) -> operations_pb2.ListOperationsResponse:
    # Create a client
    client = discoveryengine.DocumentServiceClient()

    # The full resource name of the search engine branch.
    name = f"projects/{project_id}/locations/{location}/collections/default_collection/dataStores/{search_engine_id}"
    print("name : ", name)

    # Make ListOperations request
    request = operations_pb2.ListOperationsRequest(
        name=name,
        filter=operations_filter,
    )
    print("request : ", request)

    # Make ListOperations request
    response = client.list_operations(request=request)
    # print("response.operations : ", response.operations)
    print("response : ", response)

    # Print the Operation Information
    for operation in response.operations:
        print(operation)

    return response

list_operations_sample(project_id, location, search_engine_id)


def get_operation_sample(operation_name: str) -> operations_pb2.Operation:
    # Create a client
    client = discoveryengine.DocumentServiceClient()

    # Make GetOperation request
    request = operations_pb2.GetOperationRequest(name=operation_name)
    operation = client.get_operation(request=request)

    # Print the Operation Information
    print(operation)

    return operation

# get_operation_sample("")