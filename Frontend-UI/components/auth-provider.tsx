"use client"

import { createContext, useContext, useState, useEffect, type ReactNode } from "react"
import { authService, User, AuthState } from "@/lib/auth"

interface AuthContextType extends AuthState {
  login: (email: string, password: string) => Promise<void>
  loginWithGoogle: () => Promise<void>
  logout: () => Promise<void>
  refreshAuth: () => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [authState, setAuthState] = useState<AuthState>({
    user: null,
    isAuthenticated: false,
    isLoading: true,
  })

  // Initialize auth state from storage
  useEffect(() => {
    const checkAuth = () => {
      const isAuth = authService.isAuthenticated()
      const user = authService.getCurrentUser()
      
      setAuthState({
        user,
        isAuthenticated: isAuth,
        isLoading: false,
      })
    }

    checkAuth()
  }, [])

  const login = async (email: string, password: string) => {
    setAuthState(prev => ({ ...prev, isLoading: true }))
    
    try {
      const user = await authService.authenticate(email, password)
      setAuthState({
        user,
        isAuthenticated: true,
        isLoading: false,
      })
    } catch (error) {
      setAuthState(prev => ({ ...prev, isLoading: false }))
      throw error
    }
  }

  const loginWithGoogle = async () => {
    setAuthState(prev => ({ ...prev, isLoading: true }))
    
    try {
      const user = await authService.authenticateWithGoogle()
      setAuthState({
        user,
        isAuthenticated: true,
        isLoading: false,
      })
    } catch (error) {
      setAuthState(prev => ({ ...prev, isLoading: false }))
      throw error
    }
  }

  const logout = async () => {
    setAuthState(prev => ({ ...prev, isLoading: true }))
    
    try {
      await authService.logout()
      setAuthState({
        user: null,
        isAuthenticated: false,
        isLoading: false,
      })
    } catch (error) {
      // Even if logout fails, clear local state
      setAuthState({
        user: null,
        isAuthenticated: false,
        isLoading: false,
      })
    }
  }

  const refreshAuth = () => {
    const isAuth = authService.isAuthenticated()
    const user = authService.getCurrentUser()
    
    setAuthState({
      user,
      isAuthenticated: isAuth,
      isLoading: false,
    })
  }

  return (
    <AuthContext.Provider
      value={{
        ...authState,
        login,
        loginWithGoogle,
        logout,
        refreshAuth,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider")
  }
  return context
} 