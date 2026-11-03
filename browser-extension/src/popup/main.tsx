/** Popup entry point - also serves the full-tab view via `?view=full`. */

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './App';

// The same HTML powers the 420px popup and the full-screen tab. The class swap
// must happen before first paint, or the tab renders popup-narrow for a frame.
if (new URLSearchParams(window.location.search).get('view') === 'full') {
  document.body.classList.remove('popup');
  document.body.classList.add('fullview');
}

const container = document.getElementById('root');

if (!container) {
  // popup.html always provides #root, so this only fires if the HTML was edited.
  throw new Error('Popup root element is missing.');
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
