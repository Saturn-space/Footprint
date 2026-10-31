"""Greenbone Vulnerability Management (GVM) low-level client via python-gvm and GMP protocol."""

import logging
import re
import socket
import ssl
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import xml.etree.ElementTree as ET

from app.config import settings

logger = logging.getLogger("footprintiq.integrations.greenbone")


class GreenboneConnectionStatus(str, Enum):
    """Greenbone integration readiness status."""

    READY = "READY"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    UNAVAILABLE = "UNAVAILABLE"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"


class GreenboneError(Exception):
    """Base exception for Greenbone integration errors."""
    pass


class GreenboneNotConfiguredError(GreenboneError):
    """Raised when Greenbone endpoint or credentials are not configured."""
    pass


class GreenboneConnectionError(GreenboneError):
    """Raised when connecting to the GVM daemon fails or times out."""
    pass


class GreenboneAuthenticationError(GreenboneError):
    """Raised when credentials are rejected by the GVM daemon."""
    pass


class GreenboneOperationError(GreenboneError):
    """Raised when a GMP protocol operation returns an error response."""
    pass


class GreenboneClient:
    """Low-level client for Greenbone Vulnerability Management Protocol (GMP)."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        unix_socket: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: Optional[int] = None,
        tls_verify: Optional[bool] = None,
        connection_factory: Optional[Callable[[], Any]] = None,
    ):
        self.host = host if host is not None else settings.GVM_HOST
        self.port = port if port is not None else settings.GVM_PORT
        self.unix_socket = unix_socket if unix_socket is not None else settings.GVM_UNIX_SOCKET
        self.username = username if username is not None else settings.GVM_USERNAME
        self.password = password if password is not None else settings.GVM_PASSWORD
        self.timeout = timeout if timeout is not None else settings.GVM_TIMEOUT_SECONDS
        self.tls_verify = tls_verify if tls_verify is not None else settings.GVM_TLS_VERIFY
        self._custom_connection_factory = connection_factory

    @property
    def is_configured(self) -> bool:
        """Returns True if minimum required connection parameters and credentials are set."""
        has_endpoint = bool(self.unix_socket or (self.host and self.port))
        has_credentials = bool(self.username and self.password)
        return has_endpoint and has_credentials

    @property
    def endpoint_display(self) -> str:
        """Sanitized representation of the configured target endpoint."""
        if self.unix_socket:
            return f"unix:{self.unix_socket}"
        if self.host:
            return f"{self.host}:{self.port}"
        return "none"

    def get_connection(self):
        """Constructs a python-gvm connection instance (TLS or Unix socket)."""
        if self._custom_connection_factory:
            return self._custom_connection_factory()

        if not self.is_configured:
            raise GreenboneNotConfiguredError("Greenbone service endpoint or credentials are not configured.")

        try:
            from gvm.connections import TLSConnection, UnixSocketConnection
        except ImportError as e:
            raise GreenboneConnectionError("python-gvm package is not installed.") from e

        if self.unix_socket:
            return UnixSocketConnection(path=self.unix_socket, timeout=self.timeout)

        # Network TLS connection
        return TLSConnection(
            hostname=self.host,
            port=self.port,
            timeout=self.timeout,
        )

    def check_status(self) -> Dict[str, Any]:
        """Validates configuration, connectivity, and authentication status against Greenbone.
        
        Returns a sanitized diagnostics dictionary suitable for administrative status endpoints.
        Never reveals passwords or sensitive infrastructure keys.
        """
        if not self.is_configured:
            return {
                "status": GreenboneConnectionStatus.NOT_CONFIGURED.value,
                "configured": False,
                "endpoint": self.endpoint_display,
                "version": None,
                "authenticated": False,
                "error": "Greenbone host/socket or service credentials are not configured in environment.",
            }

        try:
            from gvm.protocols.gmp import Gmp
            from gvm.errors import GvmError, GvmResponseError

            connection = self.get_connection()
            with Gmp(connection=connection) as gmp:
                try:
                    # Attempt authentication
                    gmp.authenticate(self.username, self.password)
                except (GvmResponseError, GvmError) as auth_err:
                    err_msg = str(auth_err).lower()
                    if "auth" in err_msg or "password" in err_msg or "login" in err_msg or "400" in err_msg or "401" in err_msg:
                        logger.warning("Greenbone authentication rejected for user '%s'", self.username)
                        return {
                            "status": GreenboneConnectionStatus.AUTHENTICATION_FAILED.value,
                            "configured": True,
                            "endpoint": self.endpoint_display,
                            "version": None,
                            "authenticated": False,
                            "error": "Authentication failed with configured Greenbone credentials.",
                        }
                    raise

                # Query version if authenticated
                try:
                    version_xml = gmp.get_version()
                    version = self._parse_version(version_xml)
                except Exception as ver_err:
                    logger.debug("Failed to query version: %s", ver_err)
                    version = "Unknown"

                return {
                    "status": GreenboneConnectionStatus.READY.value,
                    "configured": True,
                    "endpoint": self.endpoint_display,
                    "version": version,
                    "authenticated": True,
                    "error": None,
                }

        except ssl.SSLError as ssl_err:
            logger.error("TLS verification failed while connecting to Greenbone: %s", ssl_err)
            return {
                "status": GreenboneConnectionStatus.UNAVAILABLE.value,
                "configured": True,
                "endpoint": self.endpoint_display,
                "version": None,
                "authenticated": False,
                "error": f"TLS verification failed: {type(ssl_err).__name__}",
            }
        except (socket.error, ConnectionRefusedError, TimeoutError, OSError) as net_err:
            logger.warning("Network connection failed to Greenbone (%s): %s", self.endpoint_display, net_err)
            return {
                "status": GreenboneConnectionStatus.UNAVAILABLE.value,
                "configured": True,
                "endpoint": self.endpoint_display,
                "version": None,
                "authenticated": False,
                "error": f"Service unavailable at {self.endpoint_display}: {type(net_err).__name__}",
            }
        except Exception as e:
            logger.error("Unexpected error checking Greenbone status: %s", e)
            return {
                "status": GreenboneConnectionStatus.UNAVAILABLE.value,
                "configured": True,
                "endpoint": self.endpoint_display,
                "version": None,
                "authenticated": False,
                "error": f"Connection error: {type(e).__name__}",
            }

    def _open_session(self):
        """Context manager helper to establish an authenticated GMP session."""
        if not self.is_configured:
            raise GreenboneNotConfiguredError("Greenbone service is not configured.")

        try:
            from gvm.protocols.gmp import Gmp
            connection = self.get_connection()
            gmp = Gmp(connection=connection)
            gmp.connect()
            gmp.authenticate(self.username, self.password)
            return gmp
        except GreenboneError:
            raise
        except (socket.error, ConnectionRefusedError, TimeoutError, OSError) as e:
            raise GreenboneConnectionError(f"Failed to connect to Greenbone at {self.endpoint_display}: {e}") from e
        except Exception as e:
            err_str = str(e).lower()
            if "auth" in err_str or "credential" in err_str:
                raise GreenboneAuthenticationError("Greenbone authentication failed.") from e
            raise GreenboneConnectionError(f"Greenbone connection error: {e}") from e

    def get_version(self) -> str:
        """Retrieves the GVM protocol or daemon version."""
        gmp = self._open_session()
        try:
            res = gmp.get_version()
            return self._parse_version(res)
        finally:
            try:
                gmp.disconnect()
            except Exception:
                pass

    def get_scan_configs(self) -> List[Dict[str, str]]:
        """Retrieves available scan configurations from the Greenbone server."""
        gmp = self._open_session()
        try:
            res = gmp.get_scan_configs()
            root = ET.fromstring(res) if isinstance(res, str) else res
            configs = []
            for config in root.findall(".//config"):
                config_id = config.get("id")
                name_elem = config.find("name")
                name = name_elem.text if name_elem is not None and name_elem.text else config_id
                configs.append({"id": config_id, "name": name})
            return configs
        except Exception as e:
            logger.error("Failed to query scan configs: %s", e)
            raise GreenboneOperationError(f"Failed to retrieve scan configurations: {e}") from e
        finally:
            try:
                gmp.disconnect()
            except Exception:
                pass

    def create_target(self, name: str, hosts: List[str], port_list_id: Optional[str] = None) -> str:
        """Creates a scan target in Greenbone.
        
        Args:
            name: Target label (e.g. 'FootprintIQ-inv-123-127.0.0.1')
            hosts: List of IP addresses or hostnames
            port_list_id: Optional port list UUID
            
        Returns:
            The created target UUID.
        """
        gmp = self._open_session()
        try:
            hosts_str = ",".join(hosts)
            kwargs: Dict[str, Any] = {"name": name, "hosts": [hosts_str]}
            if port_list_id:
                kwargs["port_list_id"] = port_list_id
            
            res = gmp.create_target(**kwargs)
            root = ET.fromstring(res) if isinstance(res, str) else res
            target_id = root.get("id")
            if not target_id:
                # Some versions include <target id="...">
                target_elem = root.find(".//target")
                if target_elem is not None:
                    target_id = target_elem.get("id")
            if not target_id:
                raise GreenboneOperationError(f"Target creation did not return a target ID. Response: {ET.tostring(root, encoding='unicode')[:200]}")
            logger.info("Created Greenbone target '%s' (ID: %s)", name, target_id)
            return target_id
        except GreenboneError:
            raise
        except Exception as e:
            logger.error("Failed to create Greenbone target: %s", e)
            raise GreenboneOperationError(f"Failed to create target '{name}': {e}") from e
        finally:
            try:
                gmp.disconnect()
            except Exception:
                pass

    def create_task(self, name: str, config_id: str, target_id: str, scanner_id: Optional[str] = None) -> str:
        """Creates a vulnerability assessment task in Greenbone.
        
        Args:
            name: Task label (e.g. 'FootprintIQ-job-abc1234')
            config_id: Valid scan config UUID (e.g. Base or Full and fast)
            target_id: Target UUID
            scanner_id: Optional scanner UUID (defaults to OpenVAS default scanner)
            
        Returns:
            The created task UUID.
        """
        gmp = self._open_session()
        try:
            # OpenVAS default scanner UUID: 08b69003-5fc2-4037-a479-93b440211c73
            scanner = scanner_id or "08b69003-5fc2-4037-a479-93b440211c73"
            res = gmp.create_task(
                name=name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner,
            )
            root = ET.fromstring(res) if isinstance(res, str) else res
            task_id = root.get("id")
            if not task_id:
                task_elem = root.find(".//task")
                if task_elem is not None:
                    task_id = task_elem.get("id")
            if not task_id:
                raise GreenboneOperationError(f"Task creation did not return a task ID. Response: {ET.tostring(root, encoding='unicode')[:200]}")
            logger.info("Created Greenbone task '%s' (ID: %s)", name, task_id)
            return task_id
        except GreenboneError:
            raise
        except Exception as e:
            logger.error("Failed to create Greenbone task: %s", e)
            raise GreenboneOperationError(f"Failed to create task '{name}': {e}") from e
        finally:
            try:
                gmp.disconnect()
            except Exception:
                pass

    def start_task(self, task_id: str) -> str:
        """Starts a previously created Greenbone scan task.
        
        Returns:
            The report UUID generated for this scan run.
        """
        gmp = self._open_session()
        try:
            res = gmp.start_task(task_id=task_id)
            root = ET.fromstring(res) if isinstance(res, str) else res
            report_elem = root.find(".//report_id")
            if report_elem is not None and report_elem.text:
                report_id = report_elem.text.strip()
            else:
                report_id = root.get("id") or ""
            logger.info("Started Greenbone task '%s', report ID: %s", task_id, report_id)
            return report_id
        except Exception as e:
            logger.error("Failed to start Greenbone task '%s': %s", task_id, e)
            raise GreenboneOperationError(f"Failed to start task '{task_id}': {e}") from e
        finally:
            try:
                gmp.disconnect()
            except Exception:
                pass

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Polls task progress and status.
        
        Returns:
            dict containing:
                status: 'Running', 'Done', 'Requested', 'Stopped', 'Interrupted', etc.
                progress: integer percentage 0-100 (or -1 if unavailable)
                report_id: report UUID if available
        """
        gmp = self._open_session()
        try:
            res = gmp.get_tasks(task_id=task_id)
            root = ET.fromstring(res) if isinstance(res, str) else res
            task_elem = root.find(".//task")
            if task_elem is None:
                raise GreenboneOperationError(f"Task '{task_id}' not found in Greenbone response.")

            status_elem = task_elem.find("status")
            status = status_elem.text.strip() if status_elem is not None and status_elem.text else "Unknown"

            progress_elem = task_elem.find("progress")
            progress = 0
            if progress_elem is not None and progress_elem.text:
                try:
                    progress = max(0, min(100, int(progress_elem.text.strip())))
                except ValueError:
                    progress = 0

            report_elem = task_elem.find(".//last_report/report") or task_elem.find(".//current_report/report")
            report_id = report_elem.get("id") if report_elem is not None else None

            return {
                "status": status,
                "progress": progress,
                "report_id": report_id,
            }
        except Exception as e:
            logger.error("Failed to get task status for '%s': %s", task_id, e)
            raise GreenboneOperationError(f"Failed to query task status for '{task_id}': {e}") from e
        finally:
            try:
                gmp.disconnect()
            except Exception:
                pass

    def stop_task(self, task_id: str) -> bool:
        """Requests cancellation of a running Greenbone scan task."""
        gmp = self._open_session()
        try:
            res = gmp.stop_task(task_id=task_id)
            logger.info("Sent stop request for Greenbone task '%s'", task_id)
            return True
        except Exception as e:
            logger.error("Failed to stop Greenbone task '%s': %s", task_id, e)
            raise GreenboneOperationError(f"Failed to stop task '{task_id}': {e}") from e
        finally:
            try:
                gmp.disconnect()
            except Exception:
                pass

    def get_report_xml(self, report_id: str) -> str:
        """Retrieves the completed XML vulnerability assessment report.
        
        Args:
            report_id: UUID of the report to retrieve.
            
        Returns:
            The raw XML report string.
        """
        gmp = self._open_session()
        try:
            # Retrieve report XML with standard details
            # Anonymous XML report format UUID or default
            res = gmp.get_report(
                report_id=report_id,
                details=True,
                ignore_pagination=True,
            )
            xml_str = res if isinstance(res, str) else ET.tostring(res, encoding="utf-8").decode("utf-8")
            return xml_str
        except Exception as e:
            logger.error("Failed to retrieve Greenbone report '%s': %s", report_id, e)
            raise GreenboneOperationError(f"Failed to retrieve report '{report_id}': {e}") from e
        finally:
            try:
                gmp.disconnect()
            except Exception:
                pass

    def delete_task(self, task_id: str) -> bool:
        """Deletes a completed or cancelled task from Greenbone."""
        gmp = self._open_session()
        try:
            gmp.delete_task(task_id=task_id)
            return True
        except Exception as e:
            logger.warning("Failed to delete task '%s': %s", task_id, e)
            return False
        finally:
            try:
                gmp.disconnect()
            except Exception:
                pass

    def delete_target(self, target_id: str) -> bool:
        """Deletes a target from Greenbone."""
        gmp = self._open_session()
        try:
            gmp.delete_target(target_id=target_id)
            return True
        except Exception as e:
            logger.warning("Failed to delete target '%s': %s", target_id, e)
            return False
        finally:
            try:
                gmp.disconnect()
            except Exception:
                pass

    @staticmethod
    def _parse_version(xml_data: Any) -> str:
        """Extracts version string from get_version response."""
        try:
            root = ET.fromstring(xml_data) if isinstance(xml_data, str) else xml_data
            version_elem = root.find(".//version")
            if version_elem is not None and version_elem.text:
                return version_elem.text.strip()
            return root.text.strip() if root.text else "Unknown"
        except Exception:
            return "Unknown"
