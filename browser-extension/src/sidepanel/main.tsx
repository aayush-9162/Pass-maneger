/** Side panel entry point. */

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './App';

const container = document.getElementById('root');

if (!container) {
  // sidepanel.html always provides #root; this only fires if the HTML was edited.
  throw new Error('Side panel root element is missing.');
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
