"""Wildcard compression for package searches to reduce API calls."""

from collections import defaultdict
from typing import Dict, List, Tuple

from .entities import MaliciousPackage


class WildcardCompressor:
    """
    Compresses package searches by grouping packages with common prefixes.
    Uses word-based prefixes to minimize false positives.
    """

    def __init__(self, min_group_size: int = 2):
        """
        Initialize the wildcard compressor.

        Args:
            min_group_size: Minimum number of packages to form a wildcard group
        """
        self.min_group_size = min_group_size
        self._compression_stats = {}

    def compress_packages(
        self, packages: List[MaliciousPackage]
    ) -> Tuple[List[Tuple[str, List[MaliciousPackage]]], List[MaliciousPackage]]:
        """
        Compress packages by grouping them with common prefixes.

        Args:
            packages: List of malicious packages to compress

        Returns:
            Tuple of (wildcard_groups, standalone_packages)
            - wildcard_groups: List of (prefix, packages) tuples for wildcard searches
            - standalone_packages: Packages that don't belong to any group
        """
        # Group packages by ecosystem first
        by_ecosystem = defaultdict(list)
        for pkg in packages:
            by_ecosystem[pkg.ecosystem].append(pkg)

        all_groups = []
        all_standalone = []
        total_original = 0
        total_compressed = 0

        # Process each ecosystem separately
        for ecosystem, eco_packages in by_ecosystem.items():
            package_names = [pkg.name for pkg in eco_packages]
            total_original += len(package_names)

            # Get prefix groupings
            stats = self._analyze_prefix_compression(package_names)

            # Create wildcard groups
            groups = []
            covered_names = set()

            for prefix, names_in_group in stats["optimal_groups"].items():
                # Get the package objects for this group
                pkgs_in_group = [
                    pkg for pkg in eco_packages if pkg.name in names_in_group
                ]
                groups.append((f"{prefix}*", pkgs_in_group))
                covered_names.update(names_in_group)

            # Find standalone packages
            standalone = [pkg for pkg in eco_packages if pkg.name not in covered_names]

            all_groups.extend(groups)
            all_standalone.extend(standalone)
            total_compressed += len(groups) + len(standalone)

            # Store stats for this ecosystem
            self._compression_stats[ecosystem] = {
                "total_packages": len(package_names),
                "wildcard_groups": len(groups),
                "standalone_packages": len(standalone),
                "queries_original": len(package_names),
                "queries_compressed": len(groups) + len(standalone),
                "compression_ratio": (
                    len(package_names) / (len(groups) + len(standalone))
                    if (len(groups) + len(standalone)) > 0
                    else 1.0
                ),
            }

        # Store overall stats
        self._compression_stats["overall"] = {
            "total_packages": total_original,
            "wildcard_groups": len(all_groups),
            "standalone_packages": len(all_standalone),
            "queries_original": total_original,
            "queries_compressed": total_compressed,
            "compression_ratio": (
                total_original / total_compressed if total_compressed > 0 else 1.0
            ),
            "reduction_percentage": (
                ((total_original - total_compressed) / total_original * 100)
                if total_original > 0
                else 0
            ),
        }

        return all_groups, all_standalone

    def get_compression_stats(self) -> Dict:
        """
        Get compression statistics from the last compress_packages call.

        Returns:
            Dictionary with compression statistics
        """
        return self._compression_stats

    def _get_prefix(self, name: str) -> str:
        """
        Get the optimal prefix for a package name.

        Strategy:
        - For scoped packages (@scope/name), use the scope as prefix
        - Use first word if it's >= 3 characters
        - Use first 2 words if first word is < 3 characters
        - Use full name if only 1-2 words total

        Args:
            name: Package name

        Returns:
            Optimal prefix for grouping
        """
        # Handle scoped packages (e.g., @walletify/ui -> @walletify/)
        if name.startswith("@") and "/" in name:
            # Return scope with trailing slash (e.g., "@walletify/")
            scope_end = name.index("/")
            return name[: scope_end + 1]

        # Split by common separators (-, _, .)
        parts = name.replace("_", "-").replace(".", "-").split("-")

        if not parts:
            return name

        # If first word is >= 3 characters, use it
        if len(parts[0]) >= 3:
            return parts[0]

        # If first word is < 3 characters, use first 2 words
        if len(parts) >= 2:
            return f"{parts[0]}-{parts[1]}"

        # Only one short word, use full name (won't group well)
        return name

    def _analyze_prefix_compression(self, package_names: List[str]) -> Dict[str, any]:
        """
        Analyze package names to find common prefixes for wildcard compression.

        Args:
            package_names: List of package names to analyze

        Returns:
            Dictionary with optimal groupings
        """
        # Group by word-based prefixes
        prefix_groups = defaultdict(set)

        for name in package_names:
            prefix = self._get_prefix(name)
            prefix_groups[prefix].add(name)

        # Find optimal groupings (only keep groups with min_group_size or more)
        optimal_groups = {}
        covered_packages = set()

        # Sort by group size descending to prioritize larger groups
        sorted_prefixes = sorted(
            prefix_groups.items(), key=lambda x: len(x[1]), reverse=True
        )

        for prefix, packages in sorted_prefixes:
            # Skip if group is too small or packages already covered by another group
            if len(packages) < self.min_group_size:
                continue

            # Check how many packages in this group aren't covered yet
            uncovered = packages - covered_packages
            if len(uncovered) >= self.min_group_size:
                optimal_groups[prefix] = packages
                covered_packages.update(packages)

        return {"optimal_groups": optimal_groups, "covered_packages": covered_packages}
