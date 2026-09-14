# ---
# jupyter:
#   jupytext:
#     cell_metadata_filter: -all
#     text_representation:
#       extension: .py
#       format_name: percent
#       format_version: '1.3'
#       jupytext_version: 1.19.5
# ---

# %% [markdown]
# # Synthetic Tool-Call History
#
# This example demonstrates a minimal fake tool-calling attack using the OpenAI
# Responses API. It does not access a repository or execute tools. Instead, a YAML
# dataset defines a complete synthetic conversation containing:
#
# 1. User messages and simulated assistant review messages.
# 2. `function_call` items.
# 3. Matching `function_call_output` items.
# 4. A final user request sent to the target.
#
# ## Minimal design
#
# - **Representation:** Existing `SeedPrompt` values hold provider-shaped JSON and
#   use the existing `function_call` and `function_call_output` data types.
# - **Composition:** A shared `prompt_group_alias` and increasing `sequence` values
#   turn the seeds into one ordered `AttackSeedGroup`. The final user sequence becomes
#   `next_message`; preceding sequences become `prepended_conversation`.
# - **Execution:** `PromptSendingAttack` writes the prepended conversation to PyRIT
#   memory. `OpenAIResponseTarget` then serializes those pieces into the Responses API
#   `input` array before sending the final user message.
# - **Safety:** Calls and outputs are inert history. No tool schemas or implementations
#   are registered, so PyRIT does not execute them.
# - **Scope:** This prototype supports `OpenAIResponseTarget` only. Target requirements
#   make unsupported targets fail before an attack is sent.

# %%
import json
import os
from pathlib import Path

from pyrit.auth import get_azure_openai_auth
from pyrit.executor.attack import AttackExecutor, AttackParameters, PromptSendingAttack
from pyrit.models import AttackSeedGroup, SeedDataset
from pyrit.output import output_attack_async
from pyrit.prompt_target import CapabilityName, OpenAIResponseTarget, TargetRequirements
from pyrit.setup import IN_MEMORY, initialize_pyrit_async

await initialize_pyrit_async(  # type: ignore
    memory_db_type=IN_MEMORY,
    env_files=[],
    load_defaults=False,
    silent=True,
)

# %%
dataset_path = Path("fake_tool_call_history.yaml")
dataset = SeedDataset.from_yaml_file(dataset_path)

attack_groups = [group for group in dataset.seed_groups if isinstance(group, AttackSeedGroup)]
if len(attack_groups) != 1:
    raise ValueError(f"Expected exactly one attack seed group, found {len(attack_groups)}.")

seed_group = attack_groups[0]
params = await AttackParameters.from_seed_group_async(seed_group=seed_group)  # type: ignore

print(f"Prepended messages: {len(params.prepended_conversation or [])}")
for index, message in enumerate(params.prepended_conversation or []):
    piece = message.get_piece()
    print(index, piece.api_role, piece.converted_value_data_type)
print("Final message:", params.next_message.get_value() if params.next_message else None)

# %% [markdown]
# The output above verifies how the seed group is divided into history and the final
# request. We can also verify that every fake result references an earlier call ID.

# %%
known_call_ids: set[str] = set()
for message in params.prepended_conversation or []:
    piece = message.get_piece()
    if piece.converted_value_data_type == "function_call":
        known_call_ids.add(json.loads(piece.converted_value)["call_id"])
    elif piece.converted_value_data_type == "function_call_output":
        call_id = json.loads(piece.converted_value)["call_id"]
        if call_id not in known_call_ids:
            raise ValueError(f"Tool output references unknown call ID: {call_id}")

print("Validated call IDs:", sorted(known_call_ids))

# %% [markdown]
# ## Send the attack
#
# Set `RUN_FAKE_TOOL_HISTORY_EXAMPLE=1` and configure the standard
# `OPENAI_RESPONSES_*` environment variables to run the live request. The explicit
# requirements prevent silently flattening the structured history for an incompatible
# target.

# %%
if os.getenv("RUN_FAKE_TOOL_HISTORY_EXAMPLE") == "1":
    endpoint = os.environ["OPENAI_RESPONSES_ENDPOINT"]
    target = OpenAIResponseTarget(
        endpoint=endpoint,
        api_key=get_azure_openai_auth(endpoint),
    )

    requirements = TargetRequirements(
        native_required=frozenset(
            {
                CapabilityName.MULTI_TURN,
                CapabilityName.EDITABLE_HISTORY,
            }
        ),
        required_input_modalities=frozenset(
            {
                frozenset({"function_call"}),
                frozenset({"function_call_output"}),
            }
        ),
    )
    requirements.validate(target=target)

    attack = PromptSendingAttack(objective_target=target)
    results = await AttackExecutor().execute_attack_from_seed_groups_async(  # type: ignore
        attack=attack,
        seed_groups=[seed_group],
    )
    await output_attack_async(results.completed_results[0])
else:
    print("Live request skipped. Set RUN_FAKE_TOOL_HISTORY_EXAMPLE=1 to run it.")
