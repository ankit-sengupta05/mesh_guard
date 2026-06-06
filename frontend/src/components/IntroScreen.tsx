import React, { useEffect, useState } from 'react';
import { Shield } from 'lucide-react';

interface IntroScreenProps {
  onComplete: () => void;
}

const FULL_TEXT = 'AgentOps Security Mesh';
const SUBTITLE = 'Security Operating System for AI Agent Swarms';

export const IntroScreen: React.FC<IntroScreenProps> = ({ onComplete }) => {
  const [displayedText, setDisplayedText] = useState('');
  const [subtitleVisible, setSubtitleVisible] = useState(false);
  const [fadeOut, setFadeOut] = useState(false);
  const [charIndex, setCharIndex] = useState(0);

  useEffect(() => {
    if (charIndex < FULL_TEXT.length) {
      const timeout = setTimeout(() => {
        setDisplayedText(prev => prev + FULL_TEXT[charIndex]);
        setCharIndex(prev => prev + 1);
      }, 60);
      return () => clearTimeout(timeout);
    } else {
      // Typing done — show subtitle
      const t1 = setTimeout(() => setSubtitleVisible(true), 300);
      // Fade out after full reveal
      const t2 = setTimeout(() => setFadeOut(true), 2200);
      const t3 = setTimeout(() => onComplete(), 2700);
      return () => { clearTimeout(t1); clearTimeout(t2); clearTimeout(t3); };
    }
  }, [charIndex, onComplete]);

  return (
    <div
      className={`fixed inset-0 z-[100] bg-gray-950 flex flex-col items-center justify-center transition-opacity duration-500 ${
        fadeOut ? 'opacity-0 pointer-events-none' : 'opacity-100'
      }`}
    >
      {/* Animated grid background */}
      <div className="absolute inset-0 overflow-hidden opacity-10">
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: 'linear-gradient(rgba(59,130,246,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,0.3) 1px, transparent 1px)',
            backgroundSize: '40px 40px',
          }}
        />
      </div>

      {/* Pulsing shield icon */}
      <div className="relative mb-8">
        <div className="absolute inset-0 animate-ping opacity-20">
          <Shield size={72} className="text-blue-500" />
        </div>
        <Shield size={72} className="text-blue-500 relative z-10" />
      </div>

      {/* Typewriter title */}
      <h1 className="text-4xl md:text-5xl font-bold text-gray-100 font-mono tracking-tight mb-4 min-h-[56px]">
        {displayedText}
        <span className="animate-pulse text-blue-400">|</span>
      </h1>

      {/* Subtitle fade-in */}
      <p
        className={`text-gray-400 text-lg font-mono transition-all duration-700 ${
          subtitleVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
        }`}
      >
        {SUBTITLE}
      </p>

      {/* Loading bar */}
      <div className="mt-12 w-64 h-0.5 bg-gray-800 rounded-full overflow-hidden">
        <div
          className="h-full bg-blue-500 rounded-full transition-all ease-linear"
          style={{
            width: `${(charIndex / FULL_TEXT.length) * 100}%`,
            transitionDuration: `${60 * FULL_TEXT.length}ms`,
          }}
        />
      </div>
    </div>
  );
};
