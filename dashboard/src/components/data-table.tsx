interface Column<T> {
  header: string;
  accessor: (row: T) => React.ReactNode;
  className?: string;
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
                className={`px-4 py-3 text-left font-medium text-muted-foreground ${col.className ?? ""}`}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
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
