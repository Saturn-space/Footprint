"""High-level integration adapter orchestrating Greenbone GVM target, task, and report operations."""

import logging
from typing import Any, Dict, List, Optional
from app.integrations.greenbone_client import (
    GreenboneClient,
    GreenboneConnectionStatus,
    GreenboneError,
    GreenboneOperationError,
)
from app.services.vuln.profiles import VulnProfile

logger = logging.getLogger("footprintiq.integrations.greenbone_adapter")


class GreenboneAdapter:
    """Orchestrates Greenbone Vulnerability Management operations with server-side validations."""

    def __init__(self, client: Optional[GreenboneClient] = None):
        self.client = client or GreenboneClient()

    def check_availability(self) -> Dict[str, Any]:
        """Checks Greenbone service configuration and availability."""
        return self.client.check_status()

    def create_scan_target(self, investigation_id: str, target: str) -> str:
        """Creates a dedicated, managed GVM target object for this assessment.
        
        Names the target with strict FootprintIQ provenance prefixes.
        """
        # Controlled naming prevents collision and marks ownership
        safe_name = f"FootprintIQ-Target-{investigation_id[:8]}-{target}"
        logger.info("Provisioning Greenbone target '%s' for investigation %s", safe_name, investigation_id)
        return self.client.create_target(name=safe_name, hosts=[target])

    def create_scan_task(
        self,
        investigation_id: str,
        job_id: str,
        target_id: str,
        profile: VulnProfile,
    ) -> str:
        """Creates an assessment task in GVM bound to the vetted scan configuration profile."""
        safe_task_name = f"FootprintIQ-Task-{job_id[:12]}-{profile.id}"
        logger.info(
            "Creating Greenbone task '%s' using profile '%s' (GVM Config ID: %s)",
            safe_task_name,
            profile.id,
            profile.gvm_config_id,
        )
        return self.client.create_task(
            name=safe_task_name,
            config_id=profile.gvm_config_id,
            target_id=target_id,
        )

    def start_scan_task(self, task_id: str) -> str:
        """Starts the specified GVM scan task and returns the allocated report ID."""
        logger.info("Starting Greenbone task %s", task_id)
        return self.client.start_task(task_id=task_id)

    def poll_scan_status(self, task_id: str) -> Dict[str, Any]:
        """Polls task execution status and progress percentage."""
        status_info = self.client.get_task_status(task_id=task_id)
        logger.debug(
            "Greenbone task %s status: %s, progress: %s%%",
            task_id,
            status_info.get("status"),
            status_info.get("progress"),
        )
        return status_info

    def stop_scan_task(self, task_id: str) -> bool:
        """Requests cancellation of a running GVM scan task."""
        logger.info("Cancelling Greenbone task %s", task_id)
        return self.client.stop_task(task_id=task_id)

    def retrieve_report(self, report_id: str) -> str:
        """Retrieves the completed XML vulnerability assessment report from GVM."""
        logger.info("Retrieving Greenbone report XML for report %s", report_id)
        return self.client.get_report_xml(report_id=report_id)

    def cleanup_resources(self, task_id: Optional[str] = None, target_id: Optional[str] = None) -> None:
        """Safely cleans up ephemeral target and task objects created for the scan job."""
        if task_id:
            try:
                self.client.delete_task(task_id)
            except Exception as e:
                logger.debug("Failed to clean up task %s: %s", task_id, e)

        if target_id:
            try:
                self.client.delete_target(target_id)
            except Exception as e:
                logger.debug("Failed to clean up target %s: %s", target_id, e)
