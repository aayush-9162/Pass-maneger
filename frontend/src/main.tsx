import '@fontsource-variable/plus-jakarta-sans';

import * as React from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider } from 'react-router';

import { router } from './router';

import './globals.css';

const appName = import.meta.env.VITE_APP_NAME ?? 'PassM';
document.title = `${appName} - Internal Password Manager`;

const container = document.getElementById('root');
if (!container) throw new Error('index.html is missing the #root element.');

createRoot(container).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
);
