# Copyright 2024 s3rj1k
# SPDX-License-Identifier: Apache-2.0

"""This module provides version information"""

from importlib import metadata

try:
    __version__ = metadata.version("LibvirtIPMI")
except metadata.PackageNotFoundError:
    __version__ = "0.0.0.dev0"

__all__ = ["__version__"]
