import axios from 'axios'
import { getAdminToken } from '../lib/adminAuth'
import type { Actor, ActorListResponse, ApiStatus, DashboardStats, Threat, ThreatListResponse, TimelinePoint, XPostResult } from '../types'

const api = axios.create({ baseURL: '/api' })

api.interceptors.request.use((config) => {
  const token = getAdminToken()
  if (token) {
    config.headers = config.headers ?? {}
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// ── Dashboard ──────────────────────────────────────────────────────────────
export const getStats = async (): Promise<DashboardStats> =>
  (await api.get('/dashboard/stats')).data

export const getTimeline = async (days = 7): Promise<TimelinePoint[]> =>
  (await api.get('/dashboard/timeline', { params: { days } })).data

// ── Threats ────────────────────────────────────────────────────────────────
export const getThreats = async (params: Record<string, unknown> = {}): Promise<ThreatListResponse> =>
  (await api.get('/threats/', { params })).data

export const getThreat = async (id: number): Promise<Threat> =>
  (await api.get(`/threats/${id}`)).data

export const deleteThreat = async (id: number): Promise<ApiStatus> =>
  (await api.delete(`/threats/${id}`)).data

export const setThreatVisibility = async (id: number, isPublic: boolean): Promise<ApiStatus> =>
  (await api.patch(`/threats/${id}/visibility`, { is_public: isPublic })).data

export const setThreatVisibilityBulk = async (ids: number[], isPublic: boolean): Promise<ApiStatus> =>
  (await api.post('/threats/visibility/bulk', { ids, is_public: isPublic })).data

export const generateXPost = async (id: number): Promise<XPostResult> =>
  (await api.post(`/threats/${id}/generate-x-post`)).data

export const publishBluesky = async (id: number): Promise<XPostResult & { post_url?: string }> =>
  (await api.post(`/threats/${id}/publish-bluesky`)).data

// ── Actors ─────────────────────────────────────────────────────────────────
export const pollAllSources = async (): Promise<ApiStatus> =>
  (await api.post('/sources/poll-all')).data

export const getActors = async (params: Record<string, unknown> = {}): Promise<ActorListResponse> => {
  const res = (await api.get('/actors/', { params })).data
  return Array.isArray(res) ? { total: res.length, actors: res } : (res as ActorListResponse)
}

export const getActor = async (username: string): Promise<Actor> =>
  (await api.get(`/actors/${username}`)).data

// ── Alerts ─────────────────────────────────────────────────────────────────
export const sendTestAlert = async (): Promise<ApiStatus> =>
  (await api.post('/alerts/test')).data

export const resetDatabase = async (): Promise<ApiStatus> =>
  (await api.post('/alerts/reset-db')).data

export const deduplicateThreats = async (): Promise<ApiStatus> =>
  (await api.post('/alerts/deduplicate-threats')).data

// ── Admin Auth ───────────────────────────────────────────────────────────────
export const adminLogin = async (payload: { username: string; password: string; totp_code?: string }) =>
  (await api.post('/admin/auth/login', payload)).data

export const getAdminMe = async () => (await api.get('/admin/auth/me')).data
