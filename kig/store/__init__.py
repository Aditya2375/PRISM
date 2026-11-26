"""Key Identity Guard store package."""
from .db import get_db_path, set_db_path, get_connection, write_transaction, initialize_schema, close, reset_for_testing
from .users import User, get as get_user, create as create_user, update_status, update_epoch, seed_synthetic_users
from .audit import append as audit_append, last as audit_last, iter as audit_iter
from .keys import KeyRecord, create as key_create, get as key_get, get_latest as key_get_latest, list_versions as key_list_versions, update_state as key_update_state, delete as key_delete
from .journal import RotationEntry, append as journal_append, get as journal_get, list_for_key as journal_list_for_key, update_state as journal_update_state
from .backup_state import BackupState, create as backup_create, get as backup_get, list_all as backup_list_all, update_status as backup_update_status
from .revocations import Revocation, append as revocation_append, get as revocation_get, get_latest as revocation_get_latest, is_revoked as revocation_is_revoked, list_revocations as revocation_list_revocations, get_max_seq as revocation_get_max_seq

__all__ = [
    "get_db_path",
    "set_db_path",
    "get_connection",
    "write_transaction",
    "initialize_schema",
    "close",
    "reset_for_testing",
    "User",
    "get_user",
    "create_user",
    "update_status",
    "update_epoch",
    "seed_synthetic_users",
    "audit_append",
    "audit_last",
    "audit_iter",
    "KeyRecord",
    "key_create",
    "key_get",
    "key_get_latest",
    "key_list_versions",
    "key_update_state",
    "key_delete",
    "RotationEntry",
    "journal_append",
    "journal_get",
    "journal_list_for_key",
    "journal_update_state",
    "BackupState",
    "backup_create",
    "backup_get",
    "backup_list_all",
    "backup_update_status",
    "Revocation",
    "revocation_append",
    "revocation_get",
    "revocation_get_latest",
    "revocation_is_revoked",
    "revocation_list_revocations",
    "revocation_get_max_seq",
]