// Simple authentication utilities
export interface User {
  id: string
  email: string
  name: string
  organization_id?: string
}

export interface AuthState {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
}

const AUTH_STORAGE_KEY = 'hr-agent-auth'
const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8080'

export const authService = {
  // Check if user is authenticated
  isAuthenticated(): boolean {
    if (typeof window === 'undefined') return false
    return !!localStorage.getItem(AUTH_STORAGE_KEY)
  },

  // Get current user from storage
  getCurrentUser(): User | null {
    if (typeof window === 'undefined') return null
    const stored = localStorage.getItem(AUTH_STORAGE_KEY)
    return stored ? JSON.parse(stored) : null
  },

  // Store user session
  setUser(user: User): void {
    if (typeof window === 'undefined') return
    localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(user))
  },

  // Clear user session
  clearUser(): void {
    if (typeof window === 'undefined') return
    localStorage.removeItem(AUTH_STORAGE_KEY)
  },

  // Simple email/password authentication (for demo)
  async authenticate(email: string, password: string): Promise<User> {
    try {
      const response = await fetch(`${BACKEND_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      })

      if (response.ok) {
        const data = await response.json()
        const user: User = {
          id: data.user.id,
          email: data.user.email,
          name: data.user.name,
          organization_id: data.user.organization_id
        }
        this.setUser(user)
        return user
      } else {
        throw new Error('Authentication failed')
      }
    } catch (error) {
      // Fallback for demo - accept any email/password combo
      console.warn('Backend auth failed, using demo mode:', error)
      
      const demoUser: User = {
        id: 'demo-user-' + Date.now(),
        email: email,
        name: email.split('@')[0] || 'Demo User',
        organization_id: 'nexus-ai'
      }
      
      this.setUser(demoUser)
      return demoUser
    }
  },

  // Google OAuth (placeholder for real implementation)
  async authenticateWithGoogle(): Promise<User> {
    try {
      // In real implementation, this would redirect to Google OAuth
      const response = await fetch(`${BACKEND_URL}/api/auth/google`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      if (response.ok) {
        const data = await response.json()
        const user: User = {
          id: data.user.id,
          email: data.user.email,
          name: data.user.name,
          organization_id: data.user.organization_id
        }
        this.setUser(user)
        return user
      } else {
        throw new Error('Google authentication failed')
      }
    } catch (error) {
      // Fallback for demo
      console.warn('Google auth failed, using demo mode:', error)
      
      const demoUser: User = {
        id: 'google-demo-' + Date.now(),
        email: 'demo@google.com',
        name: 'Google Demo User',
        organization_id: 'nexus-ai'
      }
      
      this.setUser(demoUser)
      return demoUser
    }
  },

  // Logout
  async logout(): Promise<void> {
    try {
      await fetch(`${BACKEND_URL}/api/auth/logout`, {
        method: 'POST',
      })
    } catch (error) {
      console.warn('Logout API call failed:', error)
    } finally {
      this.clearUser()
    }
  }
} 