import React, { useState, useEffect, useCallback } from 'react';
import { IntroScreen } from './components/IntroScreen';
import { KeyboardShortcutsPanel } from './components/KeyboardShortcutsPanel';
import { Dashboard } from './pages/Dashboard';
import { useTheme } from './hooks/useTheme';
import { SecurityEvent } from './hooks/useWebSocket';

function App() {
  const [introComplete, setIntroComplete] = useState(false);
  const [showShortcuts, setShowShortcuts] = useState(false);
  const { theme, toggle: toggleTheme } = useTheme();

  // Global keyboard handler
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Don't fire when typing in an input
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;

      switch (e.key) {
        case '?':
          setShowShortcuts(prev => !prev);
          break;
        case 'Escape':
          setShowShortcuts(false);
          break;
        case 't':
        case 'T':
          toggleTheme();
          break;
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [toggleTheme]);

  return (
    <div className={`min-h-screen ${theme === 'dark' ? 'bg-gray-950 text-gray-300' : 'bg-gray-50 text-gray-800'}`}>
      {/* Animated intro on first load */}
      {!introComplete && (
        <IntroScreen onComplete={() => setIntroComplete(true)} />
      )}

      {/* Keyboard shortcut panel (global overlay) */}
      <KeyboardShortcutsPanel
        visible={showShortcuts}
        onClose={() => setShowShortcuts(false)}
      />

      {/* Main app — fades in after intro */}
      <div
        className={`transition-opacity duration-700 ${introComplete ? 'opacity-100' : 'opacity-0'}`}
      >
        <Dashboard
          theme={theme}
          onToggleTheme={toggleTheme}
          onShowShortcuts={() => setShowShortcuts(true)}
        />
      </div>
    </div>
  );
}

export default App;
