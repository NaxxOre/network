from dataclasses import dataclass
from typing import Optional, List, Set
from rdflib import Graph, URIRef, Namespace
from rdflib.namespace import RDF

ACL = Namespace("http://www.w3.org/ns/auth/acl#")
FOAF = Namespace("http://xmlns.com/foaf/0.1/")

@dataclass
class Decision:
    allowed: bool
    reason: str
    matched_authz: Optional[str] = None

def method_to_mode(method: str, path: str, append_only: bool) -> str:
    m = method.upper()
    # Treat ACL endpoints as "Control"
    if path.startswith("/acl/"):
        return "control"
    if m in ("GET", "HEAD", "OPTIONS"):
        return "read"
    if m in ("POST", "PATCH") and append_only:
        return "append"
    if m in ("PUT", "POST", "PATCH", "DELETE"):
        return "write"
    return "unknown"

def parse_acl_ttl(ttl: str):
    g = Graph()
    g.parse(data=ttl, format="turtle")
    return g

def allowed_by_acl(
    acl_ttl: str,
    resource_url: str,
    required_mode: str,
    webid: Optional[str],
    origin: Optional[str],
) -> Decision:
    g = parse_acl_ttl(acl_ttl)

    required_mode_uri = {
        "read": ACL.Read,
        "write": ACL.Write,
        "append": ACL.Append,
        "control": ACL.Control,
    }.get(required_mode)

    if required_mode_uri is None:
        return Decision(False, f"unsupported_mode:{required_mode}")

    # Iterate all acl:Authorization nodes
    for authz in g.subjects(RDF.type, ACL.Authorization):
        # accessTo must match resource_url
        if (authz, ACL.accessTo, URIRef(resource_url)) not in g:
            continue

        # mode must contain required mode (Append is subclass of Write in WAC, but keep MVP simple)
        modes: Set[URIRef] = set(g.objects(authz, ACL.mode))
        if required_mode_uri not in modes and not (required_mode == "append" and ACL.Write in modes):
            continue

        # Subject checks:
        # - acl:agent = specific WebID
        # - acl:agentClass foaf:Agent = public
        # - acl:agentClass acl:AuthenticatedAgent = requires some WebID
        # - acl:origin matches Origin header (optional extra constraint)
        if origin is not None and (authz, ACL.origin, URIRef(origin)) in g:
            origin_ok = True
        else:
            # if rule specifies origin(s), require match
            has_origin = any(True for _ in g.objects(authz, ACL.origin))
            origin_ok = not has_origin

        if not origin_ok:
            continue

        # specific agent
        if webid and (authz, ACL.agent, URIRef(webid)) in g:
            return Decision(True, "matched_acl_agent", str(authz))

        # public
        if (authz, ACL.agentClass, FOAF.Agent) in g:
            return Decision(True, "matched_public", str(authz))

        # authenticated agent class
        if webid and (authz, ACL.agentClass, ACL.AuthenticatedAgent) in g:
            return Decision(True, "matched_authenticated_agent", str(authz))

    return Decision(False, "no_matching_authorization")