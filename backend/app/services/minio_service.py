import asyncio
from io import BytesIO
from typing import List, Dict, Optional
import logging

from app.core.config import settings

logger = logging.getLogger("AEGIS.minio")


class MinioService:
    def __init__(self):
        self._client = None
        self._endpoint = settings.MINIO_ENDPOINT
        self._access_key = settings.MINIO_ROOT_USER
        self._secret_key = settings.MINIO_ROOT_PASSWORD
        self._secure = settings.MINIO_SECURE

    def _get_client(self):
        if self._client is False:
            return None
        if self._client is not None:
            return self._client
        try:
            from minio import Minio
            self._client = Minio(
                endpoint=self._endpoint,
                access_key=self._access_key,
                secret_key=self._secret_key,
                secure=self._secure,
            )
            return self._client
        except ImportError:
            logger.error("minio-py not installed. Object storage unavailable.")
            self._client = False
            return None
        except Exception as e:
            logger.error(f"MinIO client init failed: {e}")
            self._client = False
            return None

    async def ensure_buckets(self):
        client = self._get_client()
        if not client:
            return
        loop = asyncio.get_event_loop()
        for bucket in ["AEGIS-evidence", "AEGIS-artifacts"]:
            try:
                found = await loop.run_in_executor(None, client.bucket_exists, bucket)
                if not found:
                    await loop.run_in_executor(None, client.make_bucket, bucket)
                    try:
                        from minio.commonconfig import ENABLED
                        from minio.objectlockconfig import ObjectLockConfig
                        config = ObjectLockConfig(ENABLED)
                        await loop.run_in_executor(None, client.set_object_lock_config, bucket, config)
                    except Exception:
                        pass
                    await loop.run_in_executor(None, client.enable_versioning, bucket)
                logger.info(f"MinIO bucket '{bucket}' ready")
            except Exception as e:
                logger.warning(f"MinIO bucket '{bucket}' setup failed: {e}")

    async def upload_evidence(self, bucket: str, object_name: str, data: bytes,
                               content_type: str = "application/octet-stream",
                               legal_hold: bool = False) -> bool:
        client = self._get_client()
        if not client:
            return False
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None,
                lambda: client.put_object(
                    bucket_name=bucket,
                    object_name=object_name,
                    data=BytesIO(data),
                    length=len(data),
                    content_type=content_type,
                    legal_hold="ON" if legal_hold else "OFF",
                )
            )
            return result is not None
        except Exception as e:
            logger.error(f"MinIO upload failed: {e}")
            return False

    async def download_evidence(self, bucket: str, object_name: str) -> Optional[bytes]:
        client = self._get_client()
        if not client:
            return None
        loop = asyncio.get_event_loop()
        try:
            response = await loop.run_in_executor(
                None,
                lambda: client.get_object(bucket_name=bucket, object_name=object_name)
            )
            data = await loop.run_in_executor(None, response.read)
            await loop.run_in_executor(None, response.close)
            await loop.run_in_executor(None, response.release_conn)
            return data
        except Exception as e:
            logger.error(f"MinIO download failed: {e}")
            return None

    async def list_objects(self, bucket: str, prefix: str = "",
                            recursive: bool = True) -> List[Dict]:
        client = self._get_client()
        if not client:
            return []
        loop = asyncio.get_event_loop()
        try:
            objects = await loop.run_in_executor(
                None,
                lambda: list(client.list_objects(bucket_name=bucket, prefix=prefix, recursive=recursive))
            )
            return [
                {
                    "name": obj.object_name,
                    "size": obj.size,
                    "last_modified": str(obj.last_modified),
                    "etag": obj.etag,
                    "version_id": getattr(obj, "version_id", None),
                }
                for obj in objects
            ]
        except Exception as e:
            logger.error(f"MinIO list failed: {e}")
            return []

    async def set_legal_hold(self, bucket: str, object_name: str, hold: bool = True) -> bool:
        client = self._get_client()
        if not client:
            return False
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: client.set_object_legal_hold(
                    bucket_name=bucket,
                    object_name=object_name,
                    legal_hold="ON" if hold else "OFF",
                )
            )
            return True
        except Exception as e:
            logger.error(f"MinIO legal hold failed: {e}")
            return False

    async def delete_object(self, bucket: str, object_name: str) -> bool:
        client = self._get_client()
        if not client:
            return False
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: client.remove_object(bucket_name=bucket, object_name=object_name)
            )
            return True
        except Exception as e:
            logger.error(f"MinIO delete failed: {e}")
            return False


minio_service = MinioService()
