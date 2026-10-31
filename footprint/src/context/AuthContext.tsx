import React, { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react';
import { User, UserRole } from '../types/models';
import { DEMO_USERS, CURRENT_USER } from '../data/seedData';

interface AuthContextType {
  currentUser: User;
  token: string;
  demoUsers: readonly User[];
  loginAs: (user: User) => Promise<void>;
  logout: () => void;
  canCreateInvestigation: boolean;
  canImportActiveScans: boolean;
  canCollectPassiveData: boolean;
  canReviewFindings: boolean;
  canManageSettings: boolean;
  hasRole: (roles: UserRole[]) => boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

const STORAGE_KEY_AUTH = 'footprintiq_auth_token_v2';
const STORAGE_KEY_USER = 'footprintiq_auth_user_v2';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [currentUser, setCurrentUser] = useState<User>(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY_USER);
      if (stored) return JSON.parse(stored);
    } catch {}
    return CURRENT_USER;
  });

  const [token, setToken] = useState<string>(() => {
    return localStorage.getItem(STORAGE_KEY_AUTH) || currentUser.id;
  });

  const loginAs = useCallback(async (user: User) => {
    try {
      // Call server login endpoint
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: user.email })
      });

      if (res.ok) {
        const json = await res.json();
        if (json.success && json.data) {
          setCurrentUser(json.data.user);
          setToken(json.data.token);
          localStorage.setItem(STORAGE_KEY_USER, JSON.stringify(json.data.user));
          localStorage.setItem(STORAGE_KEY_AUTH, json.data.token);
          return;
        }
      }
    } catch {
      // Offline fallback
    }

    setCurrentUser(user);
    const fallbackToken = `token-${user.id}`;
    setToken(fallbackToken);
    localStorage.setItem(STORAGE_KEY_USER, JSON.stringify(user));
    localStorage.setItem(STORAGE_KEY_AUTH, fallbackToken);
  }, []);

  const logout = useCallback(() => {
    const viewer = DEMO_USERS.find(u => u.role === 'viewer') || DEMO_USERS[0];
    loginAs(viewer);
  }, [loginAs]);

  const hasRole = useCallback((roles: UserRole[]): boolean => {
    return roles.includes(currentUser.role);
  }, [currentUser.role]);

  const canCreateInvestigation = useMemo(() => hasRole(['admin', 'investigator']), [hasRole]);
  const canImportActiveScans = useMemo(() => hasRole(['admin', 'investigator']), [hasRole]);
  const canCollectPassiveData = useMemo(() => hasRole(['admin', 'investigator']), [hasRole]);
  const canReviewFindings = useMemo(() => hasRole(['admin', 'investigator', 'reviewer']), [hasRole]);
  const canManageSettings = useMemo(() => hasRole(['admin']), [hasRole]);

  const value = useMemo(() => ({
    currentUser,
    token,
    demoUsers: DEMO_USERS,
    loginAs,
    logout,
    canCreateInvestigation,
    canImportActiveScans,
    canCollectPassiveData,
    canReviewFindings,
    canManageSettings,
    hasRole
  }), [
    currentUser,
    token,
    loginAs,
    logout,
    canCreateInvestigation,
    canImportActiveScans,
    canCollectPassiveData,
    canReviewFindings,
    canManageSettings,
    hasRole
  ]);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
