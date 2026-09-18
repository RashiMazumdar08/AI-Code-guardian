"""
AI Code Guardian — Pandas Compatibility & Fallback Layer
=========================================================
Provides a seamless pandas interface. On systems where Windows Application
Control or OS security policies block binary .pyd C-extensions (like pandas._libs.hashing),
this module provides a pure-Python fallback (DummyDataFrame and DummySeries)
so that Streamlit dashboards and report exports continue to work cleanly.
"""
from __future__ import annotations

import csv
import io
from typing import Any

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except Exception:
    PANDAS_AVAILABLE = False

    class DummySeries(dict):
        def __init__(self, data: Any = None, name: str | None = None, dtype: Any = None):
            if isinstance(data, dict):
                super().__init__(data)
            elif isinstance(data, (list, tuple)):
                counts: dict[Any, int] = {}
                for item in data:
                    counts[item] = counts.get(item, 0) + 1
                super().__init__(counts)
            else:
                super().__init__()
            self.name = name

        def value_counts(self) -> "DummySeries":
            return self

    class DummyColumns(list):
        def tolist(self):
            return list(self)

    class DummyDataFrame(list):
        def __init__(self, data: Any = None):
            if isinstance(data, list):
                super().__init__(data)
            elif isinstance(data, dict):
                super().__init__([data])
            else:
                super().__init__()

        @property
        def columns(self):
            if not self or not isinstance(self[0], dict):
                return DummyColumns([])
            return DummyColumns(list(self[0].keys()))

        def fillna(self, value=""):
            return self

        def iterrows(self):
            for idx, row in enumerate(self):
                yield idx, row

        def to_csv(self, index: bool = False) -> str:
            if not self:
                return ""
            out = io.StringIO()
            if isinstance(self[0], dict):
                fieldnames = list(self[0].keys())
                writer = csv.DictWriter(out, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self)
            else:
                writer = csv.writer(out)
                for row in self:
                    writer.writerow([row] if not isinstance(row, (list, tuple)) else row)
            return out.getvalue()

    class DummyPandas:
        DataFrame = DummyDataFrame
        Series = DummySeries

    pd = DummyPandas()
