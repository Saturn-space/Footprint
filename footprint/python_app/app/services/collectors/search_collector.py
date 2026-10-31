"""Public search integration collector with clear NOT_CONFIGURED semantics."""

from typing import Optional
from app.services.collectors.base import BaseCollector, CollectorResult


class PublicSearchCollector(BaseCollector):
    """Integrates public search API providers when configured, else returns NOT_CONFIGURED."""

    name: str = "public_search_collector"
    source_type: str = "SEARCH_ENGINE"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    async def collect(self, target: str) -> CollectorResult:
        # If no verified external search provider is configured:
        if not self.api_key:
            return CollectorResult(
                collector_name=self.name,
                source_type=self.source_type,
                source_name="public_search",
                target=target,
                status="NOT_CONFIGURED",
                raw_content={},
                content_format="json",
                error_category="UNCONFIGURED",
                error_message="No public search API key or provider configured. Web scraping without API is disabled per project policy.",
                source_metadata={"configured": False},
            )

        # In case an API key is configured, query the search provider
        # (Reserved for future search API integrations like Bing Web Search API)
        return CollectorResult(
            collector_name=self.name,
            source_type=self.source_type,
            source_name="public_search",
            target=target,
            status="NOT_CONFIGURED",
            raw_content={},
            content_format="json",
            source_metadata={"configured": False},
        )
