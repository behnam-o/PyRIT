## Terminology

Lets clarify two concepts related to this proposal:

1. **Domain Models:** these are class definitions that contain Core business logic and rules, and other types of mdoels (ORM Models) are driven from them. Almost all classes in Pyrit represent our domain models, i.e. MessagePiece, AttackStrategy, OpenAIResponseTarget, and so on

2. **ORM models**: these are classes that help store and retrieve domain models in and from a persistence layer (e.g. a SQL database) - 

## Problem:
Often, there is parity between these Domain Models and ORM models, and a set of methods that facilitate conversions between them.

Today in PyRIT, we only have this parity between "data-bearing" components, for example MessagePiece, AttackResult, etc. We do not implement ORM Models for other "logic-bearing" components such as Attacks, Targets, Scorers. This has resulted in a few patterns, which come with their own problems:

1. Registry: an in-memory construct that holds domain models. The main problem with this is we cannot easily add/remove custom entities such as custom targets, scorers, etc. without updating source code. And our source code ends up having what is hard-coded config values (e.g. the long list of taret and socrer configs in initializers)

2. Component Identifiers: becase we don't persist descriptors/confis of logic-bearing objects as rows in memory, we do not have a good way to reference them. So we end up recreating the full logic-bearing component descriptions in data-bearing entires, called "component identifier", and store the whole JSON in the referring entities. probmlems with this:
  
		1. Copied references: A target that goes through 10 conversations appears 10 times in the "target_identifier" column of Conversation entries.
  
		2. Because we don't enforce a schema and resort to a free-form JSON string, it's easy to miss important configs/parameters of such components, and cannot guarantee the ability to reconstruct the components by simply looking at its identifier. (usually we can, but we have to be "careful" to update the identifier with necessary fields that actualy define the object, and ) 

All of these would be resolved if we have ORM models for our logic-bearing components.


## Solution: 
* All components in Pyrit must be modeled as serializable and we should habve the ability to persist them in memory, and reference them without storing full configs/descriptions of them.

* Domain models must be defined using Pydantic ORM models via SQLAlchemy. All ORM models have a backing domain model, and must implement ways to serialize/deserialize to/from them. 


## Tech Specs:
1. Both data-bearing and logic-bearing components in Pyrit must have an `id` field, which is randomly generated on creation. It is persisted as a primary key in memory and used to reference a given component in other components. 

2- 

## Phases:

1. The registry (at least object registry) becomes a thin client that simply loads entries from memory (ideally we won't even need this and the caller can just call memory, but because insantiating objects can be resource demanding, registry can be an opimization - basically a cache) 

Note: Ideally we should avoid having duplicate domain models that represent the same thing. For example, today we have `TargetConfig` whose values are repeated in targets `OpenAIChatTarget`, `OpenAIResponseTarget`, etc. This is because we are avoiding persisting the params/configs of `OpenAIResponseTarget`, but there is no reason we can't down the road. In phase 1, we will still use TargetConfig and implement the serialization/deserialization logic like today, i.e. the target ORM will have parity with `TargetConfig` fields and use `target = config.target_class(**kwargs)` to construct the actual logic-bearing objects.

2. [WIP]

# Demo: 