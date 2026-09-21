# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from collections.abc import Generator
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pyrit.backend.middleware.error_handlers import register_error_handlers
from pyrit.backend.models.datasets import DatasetInfo, DatasetListResponse, DatasetSeedInfo, DatasetSeedListResponse
from pyrit.backend.routes.datasets import router
from pyrit.backend.services.dataset_service import DatasetLoadError, DatasetService
from pyrit.memory import MemoryInterface
from pyrit.memory.memory_models import SeedEntry
from pyrit.models import SeedObjective


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    register_error_handlers(app)
    app.include_router(router, prefix="/api")
    return TestClient(app)


@pytest.fixture
def mock_service() -> Generator[MagicMock, None, None]:
    service = MagicMock(spec=DatasetService)
    service.list_dataset_seeds_async.return_value = DatasetSeedListResponse(items=[], total=0, offset=0, limit=25)
    with patch("pyrit.backend.routes.datasets.get_dataset_service", return_value=service):
        yield service


def test_list_datasets_preserves_response(*, client: TestClient, mock_service: MagicMock) -> None:
    mock_service.list_datasets_async.return_value = DatasetListResponse(
        items=[DatasetInfo(name="harmbench", is_loaded=False, can_load=True)]
    )

    response = client.get("/api/datasets")

    assert response.status_code == 200
    assert response.json() == {"items": [{"name": "harmbench", "is_loaded": False, "can_load": True}]}


@pytest.mark.parametrize("can_load", [True, False])
def test_load_dataset_returns_verified_state(*, client: TestClient, mock_service: MagicMock, can_load: bool) -> None:
    mock_service.load_dataset_async.return_value = DatasetInfo(
        name="exact / dataset", is_loaded=True, can_load=can_load
    )

    response = client.post("/api/datasets/load", json={"dataset_name": "exact / dataset"})

    assert response.status_code == 200
    assert response.json() == {"name": "exact / dataset", "is_loaded": True, "can_load": can_load}
    mock_service.load_dataset_async.assert_awaited_once_with(dataset_name="exact / dataset")


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"dataset_name": ""},
        {"dataset_name": " \t\n"},
        {"dataset_name": None},
        {"dataset_name": 12},
        {"dataset_name": ["harmbench"]},
    ],
)
def test_load_dataset_validates_nonempty_string(
    *, client: TestClient, mock_service: MagicMock, body: dict[str, object]
) -> None:
    response = client.post("/api/datasets/load", json=body)

    assert response.status_code == 422
    assert response.json()["type"] == "/errors/validation-error"
    assert response.json()["errors"][0]["field"] == "body.dataset_name"
    mock_service.load_dataset_async.assert_not_awaited()


def test_load_dataset_unknown_returns_problem_detail(*, client: TestClient, mock_service: MagicMock) -> None:
    mock_service.load_dataset_async.side_effect = FileNotFoundError("Dataset 'unknown' not found")

    response = client.post("/api/datasets/load", json={"dataset_name": "unknown"})

    assert response.status_code == 404
    assert response.json() == {
        "type": "/errors/not-found",
        "title": "Not Found",
        "status": 404,
        "detail": "Dataset 'unknown' not found",
        "instance": "/api/datasets/load",
    }


@pytest.mark.parametrize(
    "detail", ["Failed to load dataset 'harmbench'.", "Dataset 'harmbench' did not load any seeds."]
)
def test_load_dataset_failure_returns_problem_detail(
    *, client: TestClient, mock_service: MagicMock, detail: str
) -> None:
    mock_service.load_dataset_async.side_effect = DatasetLoadError(detail)

    response = client.post("/api/datasets/load", json={"dataset_name": "harmbench"})

    assert response.status_code == 500
    assert response.json() == {
        "type": "/errors/dataset-load-failed",
        "title": "Dataset Load Failed",
        "status": 500,
        "detail": detail,
        "instance": "/api/datasets/load",
    }


def test_list_dataset_seeds_defaults(*, client: TestClient, mock_service: MagicMock) -> None:
    response = client.get("/api/datasets/seeds", params={"dataset_name": "provider-only"})

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0, "offset": 0, "limit": 25}
    mock_service.list_dataset_seeds_async.assert_awaited_once_with(dataset_name="provider-only", limit=25, offset=0)


def test_list_dataset_seeds_response_and_paging(*, client: TestClient, mock_service: MagicMock) -> None:
    item = DatasetSeedInfo(
        id="a-seed-id",
        value="<script>alert('x')</script> {{7 * 7}}",
        data_type="text",
        seed_type="prompt",
    )
    mock_service.list_dataset_seeds_async.return_value = DatasetSeedListResponse(
        items=[item], total=3, offset=2, limit=1
    )

    response = client.get("/api/datasets/seeds", params={"dataset_name": " name / %_? ", "limit": 1, "offset": 2})

    assert response.status_code == 200
    assert response.json() == {
        "items": [
            {
                "id": "a-seed-id",
                "value": item.value,
                "data_type": "text",
                "seed_type": "prompt",
                "name": None,
                "role": None,
                "language": None,
                "group_id": None,
                "sequence": None,
            }
        ],
        "total": 3,
        "offset": 2,
        "limit": 1,
    }
    mock_service.list_dataset_seeds_async.assert_awaited_once_with(dataset_name=" name / %_? ", limit=1, offset=2)


def test_list_dataset_seeds_maximum_limit(*, client: TestClient, mock_service: MagicMock) -> None:
    mock_service.list_dataset_seeds_async.return_value = DatasetSeedListResponse(items=[], total=0, offset=0, limit=100)

    response = client.get("/api/datasets/seeds", params={"dataset_name": "loaded", "limit": 100})

    assert response.status_code == 200
    assert response.json()["limit"] == 100
    mock_service.list_dataset_seeds_async.assert_awaited_once_with(dataset_name="loaded", limit=100, offset=0)


@pytest.mark.usefixtures("patch_central_database")
def test_list_dataset_seeds_reads_only_loaded_memory(*, client: TestClient, sqlite_instance: MemoryInterface) -> None:
    objective = SeedObjective(value="Loaded objective", dataset_name="loaded", added_by="test")
    sqlite_instance._insert_entries(entries=[SeedEntry(entry=objective)])
    with (
        patch("pyrit.backend.routes.datasets.get_dataset_service", return_value=DatasetService()),
        patch("pyrit.backend.services.dataset_service.SeedDatasetProvider") as provider,
    ):
        loaded = client.get("/api/datasets/seeds", params={"dataset_name": "loaded"})
        unloaded = client.get("/api/datasets/seeds", params={"dataset_name": "provider-only"})

    assert loaded.status_code == 200
    assert loaded.json()["total"] == 1
    assert loaded.json()["items"][0]["value"] == objective.value
    assert unloaded.status_code == 200
    assert unloaded.json() == {"items": [], "total": 0, "offset": 0, "limit": 25}
    assert provider.mock_calls == []


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"dataset_name": ""},
        {"dataset_name": " \t\n"},
        {"dataset_name": "loaded", "limit": 0},
        {"dataset_name": "loaded", "limit": 101},
        {"dataset_name": "loaded", "limit": -1},
        {"dataset_name": "loaded", "limit": "abc"},
        {"dataset_name": "loaded", "limit": "1.5"},
        {"dataset_name": "loaded", "offset": -1},
        {"dataset_name": "loaded", "offset": "abc"},
        {"dataset_name": "loaded", "offset": "1.5"},
    ],
)
def test_list_dataset_seeds_validation(
    *, client: TestClient, mock_service: MagicMock, params: dict[str, str | int]
) -> None:
    response = client.get("/api/datasets/seeds", params=params)

    assert response.status_code == 422
    mock_service.list_dataset_seeds_async.assert_not_awaited()


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_dataset_seed_route_is_read_only(*, client: TestClient, mock_service: MagicMock, method: str) -> None:
    response = client.request(method, "/api/datasets/seeds", params={"dataset_name": "loaded"})

    assert response.status_code == 405
    mock_service.list_dataset_seeds_async.assert_not_awaited()
