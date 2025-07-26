// Authentication service for HR Agent platform
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
const TOKEN_STORAGE_KEY = 'hr-agent-token'
const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8080'

export const authService = {
  // Check if user is authenticated
  isAuthenticated(): boolean {
    if (typeof window === 'undefined') return false
    return !!localStorage.getItem(TOKEN_STORAGE_KEY)
  },

  // Get current user from storage
  getCurrentUser(): User | null {
    if (typeof window === 'undefined') return null
    const stored = localStorage.getItem(AUTH_STORAGE_KEY)
    return stored ? JSON.parse(stored) : null
  },

  // Get auth token
  getToken(): string | null {
    if (typeof window === 'undefined') return null
    return localStorage.getItem(TOKEN_STORAGE_KEY)
  },

  // Store user session and token
  setUser(user: User, token: string): void {
    if (typeof window === 'undefined') return
    localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(user))
    localStorage.setItem(TOKEN_STORAGE_KEY, token)
  },

  // Clear user session
  clearUser(): void {
    if (typeof window === 'undefined') return
    localStorage.removeItem(AUTH_STORAGE_KEY)
    localStorage.removeItem(TOKEN_STORAGE_KEY)
  },

  // Email/password authentication
  async authenticate(email: string, password: string): Promise<User> {
    try {
      console.log('🔄 Authenticating with backend...', { email, backend: BACKEND_URL })
      
      const response = await fetch(`${BACKEND_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      })

      if (response.ok) {
        const data = await response.json()
        console.log('✅ Backend authentication successful')
        
        const user: User = {
          id: data.user.id,
          email: data.user.email,
          name: data.user.name,
          organization_id: data.user.organization_id
        }
        
        this.setUser(user, data.token)
        return user
      } else {
        const errorData = await response.json()
        throw new Error(errorData.error || 'Authentication failed')
      }
    } catch (error) {
      console.error('❌ Backend auth failed:', error)
      throw error
    }
  },

  // Google OAuth authentication
  async authenticateWithGoogle(): Promise<User> {
    try {
      console.log('🔄 Authenticating with Google via backend...')
      
      const response = await fetch(`${BACKEND_URL}/api/auth/google`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}), // In real implementation, send Google token
      })

      if (response.ok) {
        const data = await response.json()
        console.log('✅ Google authentication successful')
        
        const user: User = {
          id: data.user.id,
          email: data.user.email,
          name: data.user.name,
          organization_id: data.user.organization_id
        }
        
        this.setUser(user, data.token)
        return user
      } else {
        const errorData = await response.json()
        throw new Error(errorData.error || 'Google authentication failed')
      }
    } catch (error) {
      console.error('❌ Google auth failed:', error)
      throw error
    }
  },

  // Logout
  async logout(): Promise<void> {
    try {
      const token = this.getToken()
      if (token) {
        await fetch(`${BACKEND_URL}/api/auth/logout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        })
      }
    } catch (error) {
      console.warn('Logout API call failed:', error)
    } finally {
      this.clearUser()
    }
  },

  // Verify current token and get user info
  async verifyToken(): Promise<User | null> {
    try {
      const token = this.getToken()
      if (!token) return null

      const response = await fetch(`${BACKEND_URL}/api/auth/me`, {
        headers: {
          'Authorization': `Bearer ${token}`,
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
        
        // Update stored user info
        localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(user))
        return user
      } else {
        // Token is invalid, clear it
        this.clearUser()
        return null
      }
    } catch (error) {
      console.error('Token verification failed:', error)
      this.clearUser()
      return null
    }
  }
} 