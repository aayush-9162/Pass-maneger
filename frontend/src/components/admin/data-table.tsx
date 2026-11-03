/**
 * The table every admin list is built from.
 *
 * Eleven admin screens show a paginated, sortable, filterable list of something.
 * Writing that eleven times guarantees eleven slightly different behaviours -
 * one where the page does not reset after a filter change, one where the sort
 * arrow points the wrong way, one that shows "0 of 0" while loading. So it is
 * written once here.
 *
 * Sorting and pagination are **server-side**. Client-side sorting of one page is
 * a lie: it reorders 25 rows out of 4,000 and the user believes they are looking
 * at the top of the list. Every sort here changes the query and refetches.
 */

import { ArrowDown, ArrowUp, ChevronsUpDown, Loader2, Search } from 'lucide-react';
import * as React from 'react';

import { ADMIN_PAGE_SIZES } from '@passm/shared';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { SelectCompact } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { cn } from '@/lib/utils';

export type SortDirection = 'asc' | 'desc';

export interface Column<T> {
  /** Stable key, also used as the React key for the cell. */
  key: string;
  header: React.ReactNode;
  /** Sort key sent to the API. Omit to make the column unsortable. */
  sortKey?: string;
  render: (row: T) => React.ReactNode;
  className?: string;
  headerClassName?: string;
  /**
   * Hide below the `sm` breakpoint.
   *
   * Responsive tables are a real problem: eight columns cannot fit on a phone,
   * and a horizontally scrolling table hides the actions column, which is the
   * one people came for. Secondary columns are marked here and dropped on small
   * screens, leaving identity plus actions.
   */
  hideOnMobile?: boolean;
}

export interface DataTableQuery {
  page: number;
  pageSize: number;
  sortBy?: string;
  sortDir: SortDirection;
  search: string;
}

export const DEFAULT_QUERY: DataTableQuery = {
  page: 1,
  pageSize: 25,
  sortDir: 'desc',
  search: '',
};

interface DataTableProps<T> {
  columns: readonly Column<T>[];
  rows: readonly T[] | null;
  total: number;
  query: DataTableQuery;
  onQueryChange: (query: DataTableQuery) => void;
  rowKey: (row: T) => string;
  /** True while a refetch is in flight but stale rows are still displayed. */
  refreshing?: boolean;
  emptyMessage?: string;
  searchPlaceholder?: string;
  /** Filter controls rendered beside the search box. */
  toolbar?: React.ReactNode;
  onRowClick?: (row: T) => void;
  caption?: string;
}

export function DataTable<T>({
  columns,
  rows,
  total,
  query,
  onQueryChange,
  rowKey,
  refreshing = false,
  emptyMessage = 'Nothing matches these filters.',
  searchPlaceholder = 'Search',
  toolbar,
  onRowClick,
  caption,
}: DataTableProps<T>): React.ReactElement {
  // The input is uncontrolled with respect to the query so typing stays
  // responsive; the query is updated on a debounce below.
  const [searchDraft, setSearchDraft] = React.useState(query.search);

  React.useEffect(() => {
    setSearchDraft(query.search);
  }, [query.search]);

  React.useEffect(() => {
    if (searchDraft === query.search) return undefined;

    const timer = setTimeout(() => {
      // Any change to the filter set returns to page 1. Staying on page 7 of a
      // result set that now has two pages shows an empty table and reads as a
      // bug.
      onQueryChange({ ...query, search: searchDraft, page: 1 });
    }, 300);

    return () => clearTimeout(timer);
  }, [searchDraft, query, onQueryChange]);

  const totalPages = Math.max(1, Math.ceil(total / query.pageSize));
  const firstRow = total === 0 ? 0 : (query.page - 1) * query.pageSize + 1;
  const lastRow = Math.min(total, query.page * query.pageSize);

  const toggleSort = (sortKey: string): void => {
    const sortDir: SortDirection =
      query.sortBy === sortKey && query.sortDir === 'desc' ? 'asc' : 'desc';
    onQueryChange({ ...query, sortBy: sortKey, sortDir, page: 1 });
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[12rem] flex-1">
          <Search
            className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={searchDraft}
            onChange={(event) => setSearchDraft(event.target.value)}
            placeholder={searchPlaceholder}
            aria-label={searchPlaceholder}
            className="pl-9"
          />
        </div>

        {toolbar}

        {refreshing && (
          <Loader2 className="size-4 animate-spin text-muted-foreground" aria-label="Refreshing" />
        )}
      </div>

      <div className="overflow-x-auto rounded-lg border">
        <Table>
          {caption && <caption className="sr-only">{caption}</caption>}

          <TableHeader>
            <TableRow>
              {columns.map((column) => {
                const sorted = column.sortKey !== undefined && query.sortBy === column.sortKey;
                const SortIcon = !sorted
                  ? ChevronsUpDown
                  : query.sortDir === 'asc'
                    ? ArrowUp
                    : ArrowDown;

                return (
                  <TableHead
                    key={column.key}
                    className={cn(column.hideOnMobile && 'hidden sm:table-cell', column.headerClassName)}
                    aria-sort={sorted ? (query.sortDir === 'asc' ? 'ascending' : 'descending') : undefined}
                  >
                    {column.sortKey ? (
                      <button
                        type="button"
                        onClick={() => toggleSort(column.sortKey!)}
                        className={cn(
                          'inline-flex items-center gap-1 rounded transition-colors hover:text-foreground',
                          sorted ? 'text-foreground' : 'text-muted-foreground',
                        )}
                      >
                        {column.header}
                        <SortIcon className="size-3.5" aria-hidden />
                      </button>
                    ) : (
                      column.header
                    )}
                  </TableHead>
                );
              })}
            </TableRow>
          </TableHeader>

          <TableBody>
            {rows === null ? (
              // Skeleton rows rather than a spinner: the table keeps its height,
              // so the page does not jump when the data lands.
              Array.from({ length: 5 }, (_, index) => (
                <TableRow key={`skeleton-${index}`}>
                  {columns.map((column) => (
                    <TableCell
                      key={column.key}
                      className={cn(column.hideOnMobile && 'hidden sm:table-cell')}
                    >
                      <Skeleton className="h-5" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="py-10 text-center text-sm text-muted-foreground"
                >
                  {emptyMessage}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => (
                <TableRow
                  key={rowKey(row)}
                  {...(onRowClick
                    ? {
                        onClick: () => onRowClick(row),
                        className: 'cursor-pointer',
                        tabIndex: 0,
                        role: 'button',
                        onKeyDown: (event: React.KeyboardEvent) => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault();
                            onRowClick(row);
                          }
                        },
                      }
                    : {})}
                >
                  {columns.map((column) => (
                    <TableCell
                      key={column.key}
                      className={cn(column.hideOnMobile && 'hidden sm:table-cell', column.className)}
                    >
                      {column.render(row)}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-muted-foreground">
        <div className="flex items-center gap-2">
          <span className="tabular-nums">
            {total === 0 ? 'No results' : `${firstRow}-${lastRow} of ${total.toLocaleString()}`}
          </span>

          <SelectCompact
            value={String(query.pageSize)}
            onChange={(event) =>
              onQueryChange({ ...query, pageSize: Number(event.target.value), page: 1 })
            }
            aria-label="Rows per page"
            className="w-auto"
          >
            {ADMIN_PAGE_SIZES.map((size) => (
              <option key={size} value={size}>
                {size} per page
              </option>
            ))}
          </SelectCompact>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={query.page <= 1}
            onClick={() => onQueryChange({ ...query, page: Math.max(1, query.page - 1) })}
          >
            Previous
          </Button>
          <span className="tabular-nums">
            Page {query.page} of {totalPages}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={query.page >= totalPages}
            onClick={() => onQueryChange({ ...query, page: Math.min(totalPages, query.page + 1) })}
          >
            Next
          </Button>
        </div>
      </div>
    </div>
  );
}
