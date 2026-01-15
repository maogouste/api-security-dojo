import { createContext, useContext, useState, type ReactNode } from 'react';

export interface Backend {
  id: string;
  name: string;
  baseUrl: string;
  language: string;
  icon: string;
}

export const BACKENDS: Backend[] = [
  {
    id: 'fastapi',
    name: 'FastAPI',
    baseUrl: 'http://localhost:8000',
    language: 'Python',
    icon: '🐍',
  },
  {
    id: 'express',
    name: 'Express.js',
    baseUrl: 'http://localhost:3001',
    language: 'Node.js',
    icon: '📦',
  },
  {
    id: 'go',
    name: 'Gin',
    baseUrl: 'http://localhost:3002',
    language: 'Go',
    icon: '🔷',
  },
  {
    id: 'php',
    name: 'PHP',
    baseUrl: 'http://localhost:3003',
    language: 'PHP',
    icon: '🐘',
  },
  {
    id: 'java',
    name: 'Spring Boot',
    baseUrl: 'http://localhost:3004',
    language: 'Java',
    icon: '☕',
  },
  {
    id: 'rust',
    name: 'Actix-web',
    baseUrl: 'http://localhost:3006',
    language: 'Rust',
    icon: '🦀',
  },
];

interface BackendContextType {
  backend: Backend;
  setBackend: (backend: Backend) => void;
  backends: Backend[];
}

const BackendContext = createContext<BackendContextType | null>(null);

export function BackendProvider({ children }: { children: ReactNode }) {
  const [backend, setBackendState] = useState<Backend>(() => {
    const savedId = localStorage.getItem('vulnapi_backend');
    return BACKENDS.find(b => b.id === savedId) || BACKENDS[0];
  });

  const setBackend = (newBackend: Backend) => {
    localStorage.setItem('vulnapi_backend', newBackend.id);
    setBackendState(newBackend);
    // Clear auth token when switching backends
    localStorage.removeItem('token');
  };

  return (
    <BackendContext.Provider value={{ backend, setBackend, backends: BACKENDS }}>
      {children}
    </BackendContext.Provider>
  );
}

export function useBackend() {
  const context = useContext(BackendContext);
  if (!context) {
    throw new Error('useBackend must be used within a BackendProvider');
  }
  return context;
}
