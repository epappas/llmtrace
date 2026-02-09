"use client";

import { useState, useMemo } from "react";
import { ArrowUpDown, ArrowUp, ArrowDown } from "lucide-react";

export interface Column<T> {
  header: string;
  accessor: (row: T) => React.ReactNode;
  className?: string;
  sortKey?: keyof T | ((row: T) => any);
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  onRowClick?: (row: T) => void;
  emptyMessage?: string;
}

export function DataTable<T>({
  columns,
  data,
  onRowClick,
  emptyMessage = "No data",
}: DataTableProps<T>) {
  const [sortConfig, setSortConfig] = useState<{
    key: number;
    direction: "asc" | "desc" | null;
  }>({ key: -1, direction: null });

  const sortedData = useMemo(() => {
    if (sortConfig.key === -1 || !sortConfig.direction) return data;

    const column = columns[sortConfig.key];
    const sortable = [...data].sort((a, b) => {
      let aValue = column.sortKey 
        ? (typeof column.sortKey === 'function' ? column.sortKey(a) : a[column.sortKey])
        : null;
      let bValue = column.sortKey 
        ? (typeof column.sortKey === 'function' ? column.sortKey(b) : b[column.sortKey])
        : null;

      if (aValue === bValue) return 0;
      if (aValue === null) return 1;
      if (bValue === null) return -1;

      const result = aValue < bValue ? -1 : 1;
      return sortConfig.direction === "asc" ? result : -result;
    });
    return sortable;
  }, [data, sortConfig, columns]);

  const requestSort = (index: number) => {
    let direction: "asc" | "desc" | null = "asc";
    if (sortConfig.key === index && sortConfig.direction === "asc") {
      direction = "desc";
    } else if (sortConfig.key === index && sortConfig.direction === "desc") {
      direction = null;
    }
    setSortConfig({ key: index, direction });
  };

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center rounded-md border p-8 text-sm text-muted-foreground">
        {emptyMessage}
      </div>
    );
  }

  return (
    <div className="rounded-md border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b bg-muted/50">
            {columns.map((col, i) => (
              <th
                key={i}
                className={`px-4 py-3 text-left font-medium text-muted-foreground ${col.className ?? ""} ${
                  col.sortKey ? "cursor-pointer select-none hover:text-foreground" : ""
                }`}
                onClick={() => col.sortKey && requestSort(i)}
              >
                <div className="flex items-center gap-1">
                  {col.header}
                  {col.sortKey && (
                    <span className="text-muted-foreground/50">
                      {sortConfig.key === i ? (
                        sortConfig.direction === "asc" ? <ArrowUp className="h-3 w-3" /> : 
                        sortConfig.direction === "desc" ? <ArrowDown className="h-3 w-3" /> : 
                        <ArrowUpDown className="h-3 w-3" />
                      ) : (
                        <ArrowUpDown className="h-3 w-3" />
                      )}
                    </span>
                  )}
                </div>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sortedData.map((row, i) => (
            <tr
              key={i}
              onClick={() => onRowClick?.(row)}
              className={`border-b transition-colors hover:bg-muted/50 ${onRowClick ? "cursor-pointer" : ""}`}
            >
              {columns.map((col, j) => (
                <td key={j} className={`px-4 py-3 ${col.className ?? ""}`}>
                  {col.accessor(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
