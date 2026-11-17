"""Bind signed public bytes to a separately approved, private first-adoption plan.

No signing, service operations, extraction to the host, or legacy-version fiction.
The approval digest is supplied out of band, never trusted from the packet itself.
"""
import json
import tempfile
from pathlib import Path
from release import canonical, sha, inspect, extract_verified

PRODUCT_KEY_SHA256 = '6adf5e38d694aa4b16c74c28e50bb197e4d617035b39e03aaad8e7d39e973e5e'

def require(value, reason):
    if not value:raise ValueError(reason)

def inventory(files):
    return {name:{'sha256':sha(raw),'mode':mode} for name,(raw,mode) in sorted(files.items()) if name!='bundle.json'}

def check_plan(plan, content, review, service_contract):
    require(plan.get('kind')=='existing-host-adoption' and plan.get('source')=='unregistered-existing-host','adoption_plan_kind')
    require(plan['target']=={'version':review['release']['version'],'release_sha256':review['release']['sha256']},'adoption_plan_release')
    paths=[row['path'] for row in plan['changes']]
    require(len(paths)==len(set(paths)) and set(paths)==set(content),'adoption_plan_content_inventory')
    require(not set(paths)&set(service_contract['definition_guards']),'adoption_protected_definition_mutation')
    require(sha(canonical(plan))==review['plan_sha256'],'adoption_plan_binding')
    require(sha(canonical({p:sha(raw) for p,raw in sorted(content.items())}))==review['content_sha256'],'adoption_content_binding')
    return {'status':'PASS'}

def verify_assets(archive, metadata, signature, public_key, review, expected_review_sha256,
                  preservation, service_contract, *, openssl='openssl'):
    require(sha(canonical(review))==expected_review_sha256,'adoption_review_digest')
    require(review.get('format')==1 and review.get('kind')=='signed-existing-host-adoption', 'adoption_binding_kind')
    require(review.get('source')=='unregistered-existing-host','adoption_binding_source')
    require(review.get('production_ready') is True,'adoption_binding_not_ready')
    require(sha(Path(public_key).read_bytes())==PRODUCT_KEY_SHA256==review['public_key_sha256'],'adoption_signing_key')
    require(metadata==review['release'],'adoption_release_metadata')
    require(sha(canonical(preservation))==review['preservation_sha256'],'adoption_preservation_binding')
    require(sha(canonical(service_contract))==review['service_contract_sha256'],'adoption_service_binding')
    manifest,files=inspect(archive,metadata,signature,public_key,openssl)
    # An individually approved first adoption must never become an ordinary
    # fresh-install/automatic-update artifact merely to pass this verifier.
    require(manifest.get('install_ready') is False and review.get('scope')=='existing-host-only',
            'adoption_release_scope')
    require(sha(canonical(inventory(files)))==review['payload_inventory_sha256'],'adoption_payload_inventory')
    from native_requirements import DESCRIPTOR, validate
    require(DESCRIPTOR in files,'adoption_native_descriptor_missing')
    native=validate(json.loads(files[DESCRIPTOR][0]))
    require(sha(canonical(native))==review['native_requirements_sha256'],'adoption_native_binding')
    # A first-adoption bundle is not a normal version-to-version update contract.
    require('payload/blueprint/update-contract.json' not in files,'adoption_legacy_contract_present')
    return manifest,files

def compile_verified(files, metadata, review, service_contract, preservation, *, site, identities,
                     live, exists, native, module, module_metadata, checks, updater_registration=None, sieve_layout=None, code_aliases=None):
    """Compile only from bytes returned by verify_assets, then require reviewed plan."""
    inputs={'site':site,'identities':identities,'native':native,
            'module_sha256':sha(module),'module_metadata':module_metadata,'checks':checks}
    if updater_registration is not None:
        inputs['updater_registration']={'public_key_sha256':sha(updater_registration['public_key']),
                                        'allowed_uid':updater_registration['allowed_uid']}
    if sieve_layout is not None:inputs['sieve_layout']=sieve_layout
    if code_aliases:inputs['code_aliases']=code_aliases
    require(sha(canonical(inputs))==review['compiler_inputs_sha256'],'adoption_compiler_inputs')
    require(sha(canonical(native))==review['native_requirements_sha256'],'adoption_native_binding')
    require(sha(canonical(inventory(files)))==review['payload_inventory_sha256'],'adoption_verified_bytes_changed')
    from adoption_components import compile_components
    with tempfile.TemporaryDirectory(prefix='mail-adoption-verified-') as temporary:
        stage=extract_verified(files,Path(temporary)/'release')
        plan,content,receipt=compile_components(stage/'payload',site,identities,live,exists,
            native=native,module=module,module_metadata=module_metadata,
            version=metadata['version'],release_sha256=metadata['sha256'],checks=checks,
            updater_registration=updater_registration,sieve_layout=sieve_layout,code_aliases=code_aliases)
    check_plan(plan,content,review,service_contract)
    return plan,content,receipt

def prepare_verified(archive, metadata, signature, public_key, review, expected_review_sha256,
                     preservation, service_contract, *, openssl='openssl', **inputs):
    _,files=verify_assets(archive,metadata,signature,public_key,review,expected_review_sha256,
                         preservation,service_contract,openssl=openssl)
    return compile_verified(files,metadata,review,service_contract,preservation,**inputs)

def protected_host(evidence, review, service_contract, preflight, verification, *, enrollment_contract, enrollment_probe, sieve_layout):
    """Production integration cannot opt out of dependency/definition protection."""
    require(review.get('production_ready') is True,'adoption_binding_not_ready')
    require(sha(canonical(service_contract))==review['service_contract_sha256'],'adoption_service_binding')
    require(sha(canonical(enrollment_contract))==review['enrollment_contract_sha256'],'adoption_enrollment_binding')
    require(sha(canonical(sieve_layout))==review['sieve_layout_sha256'],'adoption_Sieve_layout_binding')
    from adoption_host import AdoptionHost
    from adoption_review import Protection
    from adoption_enrollment import Enrollment
    host=AdoptionHost(evidence,service_contract['services'],service_contract['dependency_guards'],preflight,verification)
    host.protection=Protection(service_contract,host.commands)
    host.enrollment=Enrollment(evidence,enrollment_contract,host.commands,enrollment_probe)
    host.sieve_layout=sieve_layout
    return host
