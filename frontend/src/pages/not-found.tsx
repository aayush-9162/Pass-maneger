import * as React from 'react';
import { Link } from 'react-router';

import { Button } from '@/components/ui/button';

/** Any path the route table does not know. */
export default function NotFoundPage(): React.ReactElement {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 p-6 text-center">
      <h1 className="text-2xl font-semibold">Page not found</h1>
      <p className="text-sm text-muted-foreground">
        Nothing lives at this address. It may have moved, or the link may be mistyped.
      </p>
      <Button asChild>
        <Link to="/">Go to PassM</Link>
      </Button>
    </div>
  );
}
