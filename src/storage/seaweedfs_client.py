"""
FootprintIQ - SeaweedFS Object Storage Client
Handles evidence preservation, file assignment, uploading, downloading,
integrity verification (SHA-256), and metadata tracking.
"""

import os
import io
import hashlib
import logging
from typing import Optional, Dict, Any, Tuple
import requests

logger = logging.getLogger("FootprintIQ.SeaweedFS")

DEFAULT_MASTER_URL = os.getenv("SEAWEEDFS_MASTER_URL", "http://127.0.0.1:9333")
DEFAULT_CACHE_DIR = os.getenv("EVIDENCE_CACHE_DIR", os.path.abspath("data/evidence_cache"))


class SeaweedFSClient:
    def __init__(self, master_url: str = DEFAULT_MASTER_URL, cache_dir: str = DEFAULT_CACHE_DIR, timeout: int = 15):
        self.master_url = master_url.rstrip("/")
        self.cache_dir = cache_dir
        self.timeout = timeout
        os.makedirs(self.cache_dir, exist_ok=True)

    def check_health(self) -> Dict[str, Any]:
        """
        Queries SeaweedFS master health and cluster readiness.
        """
        try:
            resp = requests.get(f"{self.master_url}/dir/assign", timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "status": "ONLINE",
                    "master_url": self.master_url,
                    "volume_url": data.get("url"),
                    "can_assign": True
                }
            return {
                "status": "DEGRADED",
                "master_url": self.master_url,
                "http_status": resp.status_code
            }
        except Exception as e:
            return {
                "status": "OFFLINE",
                "master_url": self.master_url,
                "error": str(e)
            }

    def assign_fid(self, collection: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        """
        Requests a new File ID (fid) and Volume URL from SeaweedFS Master.
        Returns: (fid, volume_url)
        """
        try:
            url = f"{self.master_url}/dir/assign"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if "fid" in data and "url" in data:
                    fid = data.get("fid")
                    vol_url = data.get("url")
                    if vol_url and not vol_url.startswith("http"):
                        vol_url = f"http://{vol_url}"
                    return fid, vol_url
        except Exception as e:
            logger.warning(f"SeaweedFS assign failed: {e}")
        return None, None

    def upload_content(
        self,
        content: bytes,
        file_name: str,
        investigation_id: str,
        evidence_type: str,
        content_type: str = "application/octet-stream"
    ) -> Dict[str, Any]:
        """
        Uploads in-memory bytes to SeaweedFS with SHA-256 integrity calculation.
        Falls back to local cache if SeaweedFS master is unreachable.
        """
        sha256_hash = hashlib.sha256(content).hexdigest()
        file_size = len(content)

        # Always maintain a secure local copy in evidence cache
        inv_cache_dir = os.path.join(self.cache_dir, investigation_id)
        os.makedirs(inv_cache_dir, exist_ok=True)
        local_path = os.path.join(inv_cache_dir, f"{sha256_hash}_{file_name}")
        with open(local_path, "wb") as f:
            f.write(content)

        fid, volume_url = self.assign_fid(collection=investigation_id)
        seaweed_url = None

        if fid and volume_url:
            try:
                upload_endpoint = f"{volume_url}/{fid}"
                files = {"file": (file_name, io.BytesIO(content), content_type)}
                up_resp = requests.post(upload_endpoint, files=files, timeout=self.timeout)
                if up_resp.status_code in (200, 201):
                    seaweed_url = upload_endpoint
                    logger.info(f"Successfully uploaded {file_name} to SeaweedFS (FID: {fid})")
            except Exception as e:
                logger.warning(f"Failed to upload to volume server: {e}")

        return {
            "file_name": file_name,
            "file_size": file_size,
            "content_type": content_type,
            "sha256_hash": sha256_hash,
            "seaweed_fid": fid,
            "seaweed_url": seaweed_url,
            "local_path": local_path,
            "investigation_id": investigation_id,
            "evidence_type": evidence_type,
            "storage_provider": "SeaweedFS" if seaweed_url else "LocalStorageCache"
        }

    def upload_file(
        self,
        file_path: str,
        investigation_id: str,
        evidence_type: str,
        content_type: str = "application/octet-stream"
    ) -> Dict[str, Any]:
        """
        Uploads an existing file from disk to SeaweedFS.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_name = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            content = f.read()

        return self.upload_content(
            content=content,
            file_name=file_name,
            investigation_id=investigation_id,
            evidence_type=evidence_type,
            content_type=content_type
        )

    def download_content(self, seaweed_fid: Optional[str], local_path: Optional[str] = None) -> Optional[bytes]:
        """
        Retrieves file bytes from SeaweedFS volume or local cache.
        """
        if seaweed_fid:
            try:
                # Ask master for volume location
                lookup_url = f"{self.master_url}/dir/lookup?volumeId={seaweed_fid.split(',')[0]}"
                resp = requests.get(lookup_url, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    locations = data.get("locations", [])
                    if locations:
                        vol_url = locations[0].get("url")
                        if vol_url and not vol_url.startswith("http"):
                            vol_url = f"http://{vol_url}"
                        dl_resp = requests.get(f"{vol_url}/{seaweed_fid}", timeout=self.timeout)
                        if dl_resp.status_code == 200:
                            return dl_resp.content
            except Exception as e:
                logger.warning(f"SeaweedFS retrieval failed for FID {seaweed_fid}: {e}")

        # Fallback to local cached file
        if local_path and os.path.exists(local_path):
            with open(local_path, "rb") as f:
                return f.read()

        return None
