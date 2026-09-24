"""Compile approved control-plane packages into F0 operations.

Packages are not incident evidence.  Metadata never grants proof.  An asset
is F0 only after explicit approval and conformance fixtures, and it still
enters the same Observation / ProofContract path as any other operation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from hunting.contracts.lifecycle import (
    AnalyticPackage,
    CapabilityArtifact,
    HuntPackage,
    LifecycleStatus,
)
from hunting.contracts.queries import ProviderOperation
from hunting.contracts.query_intent import QueryIntentSpec

F0_PACKAGE_PROVENANCE = "F0_PACKAGE"
RETRIEVAL_FIXTURES = ("positive", "negative")
PROOF_FIXTURES = ("positive", "negative", "unrelated_row", "role_swap")


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value in (None, ""):
        return ()
    if isinstance(value, str):
        return (value,) if value.strip() else ()
    return tuple(str(item) for item in value if str(item).strip())


def _as_bindings(value: Any) -> dict[str, tuple[str, ...]]:
    return {
        str(role): _as_tuple(fields)
        for role, fields in dict(value or {}).items()
        if str(role).strip()
    }


def fixture_names(item: Any) -> set[str]:
    names = set(_as_tuple(getattr(item, "fixtures", ()) or ()))
    names.update(str(item_name).casefold() for item_name in _as_tuple(getattr(item, "tests", ()) or ()))
    return {name.casefold() for name in names}


def has_named_fixture(names: set[str], required: str) -> bool:
    wanted = required.casefold()
    return any(wanted == name or wanted.replace("_", " ") in name or wanted in name for name in names)


def required_fixtures(item: Any) -> tuple[str, ...]:
    contract = dict(getattr(item, "completeness_contract", {}) or {})
    if contract.get("proof_contract_id") or str(contract.get("proof_mode", "")).casefold() == "prove":
        return PROOF_FIXTURES
    return RETRIEVAL_FIXTURES


def declares_completeness_or_limitations(item: Any) -> bool:
    return bool(tuple(getattr(item, "limitations", ()) or ())) or bool(
        dict(getattr(item, "completeness_contract", {}) or {})
    )


def fixtures_satisfied(item: Any) -> bool:
    names = fixture_names(item)
    return all(has_named_fixture(names, required) for required in required_fixtures(item))


def is_f0_asset(item: Any) -> bool:
    if getattr(item, "status", None) != LifecycleStatus.APPROVED:
        return False
    if not fixtures_satisfied(item):
        return False
    if isinstance(item, CapabilityArtifact):
        return bool(item.provider_compiler_ref)
    if isinstance(item, AnalyticPackage):
        return bool(item.internal_representation or item.semantic_expression)
    if isinstance(item, HuntPackage):
        return bool(item.graph_template)
    return False


@dataclass(frozen=True)
class AnalyticIR:
    package_id: str
    package_version: str
    input_roles: tuple[str, ...]
    output_roles: tuple[str, ...]
    input_entity_kinds: tuple[str, ...]
    output_entity_kinds: tuple[str, ...]
    native_field_bindings: dict[str, tuple[str, ...]]
    output_value_bindings: dict[str, tuple[str, ...]]
    supported_constraints: tuple[str, ...]
    projection_roles: tuple[str, ...]
    transformations_applied: tuple[str, ...]
    compiler_ref: str = ""
    schema_version: str = ""
    parser_version: str = ""
    proof_contract_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "package_version": self.package_version,
            "input_roles": list(self.input_roles),
            "output_roles": list(self.output_roles),
            "input_entity_kinds": list(self.input_entity_kinds),
            "output_entity_kinds": list(self.output_entity_kinds),
            "native_field_bindings": {key: list(value) for key, value in self.native_field_bindings.items()},
            "output_value_bindings": {key: list(value) for key, value in self.output_value_bindings.items()},
            "supported_constraints": list(self.supported_constraints),
            "projection_roles": list(self.projection_roles),
            "transformations_applied": list(self.transformations_applied),
            "compiler_ref": self.compiler_ref,
            "schema_version": self.schema_version,
            "parser_version": self.parser_version,
            "proof_contract_id": self.proof_contract_id,
        }


def compile_analytic_ir(package: AnalyticPackage) -> AnalyticIR:
    expression = dict(package.semantic_expression or {})
    raw = dict(package.internal_representation or {})
    input_roles = _as_tuple(raw.get("input_roles") or expression.get("input_roles"))
    output_roles = _as_tuple(raw.get("output_roles") or expression.get("output_roles"))
    input_kinds = _as_tuple(
        raw.get("input_entity_kinds")
        or expression.get("input_entity_kinds")
        or expression.get("subject_type")
    )
    output_kinds = _as_tuple(
        raw.get("output_entity_kinds")
        or expression.get("output_entity_kinds")
        or expression.get("object_type")
    )
    bindings = _as_bindings(raw.get("native_field_bindings") or expression.get("native_field_bindings"))
    outputs = _as_bindings(raw.get("output_value_bindings") or expression.get("output_value_bindings"))
    constraints = _as_tuple(raw.get("supported_constraints") or expression.get("supported_constraints"))
    projection = _as_tuple(raw.get("projection_roles") or output_roles)
    applied: list[str] = []
    transforms = tuple(package.transformations or ())
    if not transforms:
        transforms = (
            {"stage": "normalize_roles"},
            {"stage": "project_fields"},
        )
    for transform in transforms:
        if not isinstance(transform, Mapping):
            raise ValueError("analytic transformation must be an object")
        stage = str(transform.get("stage") or "").strip().casefold()
        if stage == "normalize_roles":
            mapping = {str(key).casefold(): str(value) for key, value in dict(transform.get("mapping") or {}).items()}
            if mapping:
                input_roles = tuple(mapping.get(role.casefold(), role) for role in input_roles)
                output_roles = tuple(mapping.get(role.casefold(), role) for role in output_roles)
            applied.append(stage)
        elif stage == "project_fields":
            projected = _as_tuple(transform.get("roles") or projection)
            if projected:
                projection = projected
            applied.append(stage)
        elif stage == "apply_constraints":
            constraints = tuple(dict.fromkeys(constraints + _as_tuple(transform.get("constraints"))))
            applied.append(stage)
        else:
            raise ValueError(f"unknown analytic transform stage: {stage}")
    contract = dict(package.completeness_contract or {})
    return AnalyticIR(
        package_id=package.id,
        package_version=package.version,
        input_roles=input_roles,
        output_roles=output_roles,
        input_entity_kinds=input_kinds,
        output_entity_kinds=output_kinds,
        native_field_bindings=bindings,
        output_value_bindings=outputs,
        supported_constraints=constraints,
        projection_roles=projection,
        transformations_applied=tuple(applied),
        compiler_ref=str(raw.get("compiler_ref") or expression.get("compiler_ref") or ""),
        schema_version=str(raw.get("schema_version") or ""),
        parser_version=str(raw.get("parser_version") or ""),
        proof_contract_id=str(contract.get("proof_contract_id") or "") or None,
    )


def _operation_from_ir(
    *,
    operation_id: str,
    provider_id: str,
    compiler_ref: str,
    input_roles: tuple[str, ...],
    output_roles: tuple[str, ...],
    input_kinds: tuple[str, ...],
    output_kinds: tuple[str, ...],
    native_field_bindings: dict[str, tuple[str, ...]],
    output_value_bindings: dict[str, tuple[str, ...]],
    supported_constraints: tuple[str, ...],
    schema_fingerprint: str,
    package_id: str,
    package_version: str,
    proof_contract_id: str | None = None,
) -> ProviderOperation:
    if not compiler_ref:
        raise ValueError("F0 package operation requires a provider compiler reference")
    return ProviderOperation(
        id=operation_id,
        provider_id=provider_id,
        scope_ids=(),
        query_builder=compiler_ref,
        input_roles=input_roles,
        output_roles=output_roles,
        input_entity_kinds=input_kinds,
        output_entity_kinds=output_kinds,
        native_field_bindings=dict(native_field_bindings),
        output_value_bindings=dict(output_value_bindings) or (
            {"object": output_roles} if output_roles else {}
        ),
        supported_constraints=supported_constraints,
        schema_fingerprint=schema_fingerprint,
        discovery_provenance=(F0_PACKAGE_PROVENANCE, package_id, package_version),
        route_class="EXECUTABLE",
        route_mode="PROVE" if proof_contract_id else "EXPLORE",
        proof_contract_id=proof_contract_id,
        proof_mode="relation_observable",
        runtime_source_id=f"package:{package_id}",
    )


class PackageBackendCompiler:
    """Provider-neutral backend interface. Adapters still compile native queries."""

    def compile(self, ir: AnalyticIR, *, provider_id: str) -> ProviderOperation:
        return _operation_from_ir(
            operation_id=f"package:{ir.package_id}@{ir.package_version}",
            provider_id=provider_id,
            compiler_ref=ir.compiler_ref or "package.analytic.v1",
            input_roles=ir.input_roles,
            output_roles=ir.output_roles,
            input_kinds=ir.input_entity_kinds,
            output_kinds=ir.output_entity_kinds,
            native_field_bindings=ir.native_field_bindings,
            output_value_bindings=ir.output_value_bindings,
            supported_constraints=ir.supported_constraints,
            schema_fingerprint=ir.schema_version,
            package_id=ir.package_id,
            package_version=ir.package_version,
            proof_contract_id=ir.proof_contract_id,
        )

    def compile_intent(self, ir: AnalyticIR, *, goal_id: str, relation: str, provider_id: str) -> QueryIntentSpec:
        operation = self.compile(ir, provider_id=provider_id)
        return QueryIntentSpec(
            goal_id=goal_id,
            operation_id=operation.id,
            source_id=operation.runtime_source_id or operation.id,
            relation=relation,
            projection_roles=ir.projection_roles,
            expected_output=ir.output_roles,
            mode="EXPLORE",
        )


def compile_capability_artifact(artifact: CapabilityArtifact, *, provider_id: str) -> ProviderOperation:
    if not is_f0_asset(artifact):
        raise ValueError("capability artifact is not an F0 asset")
    ir = dict(artifact.completeness_contract.get("operation_ir") or {})
    types = artifact.supported_entity_types
    input_kinds = _as_tuple(ir.get("input_entity_kinds")) or ((types[0],) if types else ())
    output_kinds = _as_tuple(ir.get("output_entity_kinds")) or ((types[-1],) if types else ())
    return _operation_from_ir(
        operation_id=f"package:{artifact.id}@{artifact.version}",
        provider_id=provider_id,
        compiler_ref=artifact.provider_compiler_ref,
        input_roles=artifact.input_roles,
        output_roles=artifact.output_roles,
        input_kinds=input_kinds,
        output_kinds=output_kinds,
        native_field_bindings=_as_bindings(ir.get("native_field_bindings")),
        output_value_bindings=_as_bindings(ir.get("output_value_bindings")),
        supported_constraints=artifact.supported_constraints,
        schema_fingerprint=artifact.schema_version,
        package_id=artifact.id,
        package_version=artifact.version,
        proof_contract_id=str(artifact.completeness_contract.get("proof_contract_id") or "") or None,
    )


def compile_analytic_package(package: AnalyticPackage, *, provider_id: str) -> ProviderOperation:
    if not is_f0_asset(package):
        raise ValueError("analytic package is not an F0 asset")
    backends = tuple(str(item) for item in package.supported_backends)
    if backends and provider_id not in backends:
        raise ValueError("analytic package does not support this provider")
    return PackageBackendCompiler().compile(compile_analytic_ir(package), provider_id=provider_id)


def compile_hunt_package(
    package: HuntPackage,
    *,
    provider_id: str,
    artifacts: Iterable[CapabilityArtifact] = (),
) -> tuple[ProviderOperation, ...]:
    if not is_f0_asset(package):
        raise ValueError("hunt package is not an F0 asset")
    template = dict(package.graph_template or {})
    operations: list[ProviderOperation] = []
    artifact_by_id = {(item.id, item.version): item for item in artifacts}
    for ref in template.get("capability_artifact_ids") or ():
        if isinstance(ref, Mapping):
            key = (str(ref.get("id", "")), str(ref.get("version", "")))
        else:
            key = (str(ref), "")
        artifact = artifact_by_id.get(key)
        if artifact is None and key[1] == "":
            artifact = next((item for item in artifacts if item.id == key[0]), None)
        if artifact is None:
            continue
        if is_f0_asset(artifact):
            operations.append(compile_capability_artifact(artifact, provider_id=provider_id))
    operation_ir = template.get("operation_ir")
    if isinstance(operation_ir, Mapping) and operation_ir:
        synthetic = CapabilityArtifact(
            id=package.id,
            version=package.version,
            owner=package.owner,
            status=package.status,
            input_roles=_as_tuple(operation_ir.get("input_roles")),
            output_roles=_as_tuple(operation_ir.get("output_roles")),
            provider_compiler_ref=str(operation_ir.get("compiler_ref") or "package.hunt.v1"),
            supported_entity_types=_as_tuple(operation_ir.get("supported_entity_types")),
            supported_constraints=_as_tuple(operation_ir.get("supported_constraints")),
            completeness_contract={
                **dict(package.completeness_contract or {}),
                "operation_ir": dict(operation_ir),
            },
            limitations=package.limitations,
            fixtures=package.tests,
        )
        operations.append(compile_capability_artifact(synthetic, provider_id=provider_id))
    return tuple(operations)


def f0_operations_from_registry(registry: Any, provider_id: str) -> tuple[ProviderOperation, ...]:
    if registry is None:
        return ()
    items = tuple(registry.list())
    artifacts = tuple(item for item in items if isinstance(item, CapabilityArtifact))
    operations: list[ProviderOperation] = []
    seen: set[str] = set()
    for item in items:
        compiled: tuple[ProviderOperation, ...] = ()
        try:
            if isinstance(item, CapabilityArtifact) and is_f0_asset(item):
                compiled = (compile_capability_artifact(item, provider_id=provider_id),)
            elif isinstance(item, AnalyticPackage) and is_f0_asset(item):
                if item.supported_backends and provider_id not in item.supported_backends:
                    continue
                compiled = (compile_analytic_package(item, provider_id=provider_id),)
            elif isinstance(item, HuntPackage) and is_f0_asset(item):
                compiled = compile_hunt_package(item, provider_id=provider_id, artifacts=artifacts)
        except ValueError:
            continue
        for operation in compiled:
            if operation.id in seen:
                continue
            seen.add(operation.id)
            operations.append(operation)
    return tuple(operations)


def merge_f0_operations(
    operations: Iterable[ProviderOperation],
    registry: Any,
    provider_id: str,
) -> tuple[ProviderOperation, ...]:
    package_ops = f0_operations_from_registry(registry, provider_id)
    if not package_ops:
        return tuple(operations)
    existing = {operation.id for operation in operations}
    merged = list(package_ops)
    merged.extend(operation for operation in operations if operation.id not in existing)
    return tuple(merged)


__all__ = [
    "F0_PACKAGE_PROVENANCE",
    "AnalyticIR",
    "PackageBackendCompiler",
    "compile_analytic_ir",
    "compile_analytic_package",
    "compile_capability_artifact",
    "compile_hunt_package",
    "declares_completeness_or_limitations",
    "f0_operations_from_registry",
    "fixtures_satisfied",
    "is_f0_asset",
    "merge_f0_operations",
    "required_fixtures",
]
