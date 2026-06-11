import { useState } from 'react'
import { Bell, CheckCircle, XCircle, Loader2 } from 'lucide-react'
import { sendTestAlert } from '../api/client'

type Status = { ok: boolean; detail: string } | null

export default function Alerts() {
  const [testStatus, setTestStatus] = useState<Status>(null)
  const [testLoading, setTestLoading] = useState(false)

  const handleTestAlert = async () => {
    setTestLoading(true)
    setTestStatus(null)
    try {
      const res = await sendTestAlert()
      setTestStatus(res)
    } catch (e: any) {
      setTestStatus({ ok: false, detail: e?.response?.data?.detail ?? 'Request failed' })
    } finally {
      setTestLoading(false)
    }
  }

  return (
    <div className="space-y-4 p-1">
      <div className="bg-[#0d0d16] border border-[#1a1a28] p-4 rounded">
        <div className="flex items-center gap-2 mb-3">
          <Bell size={14} className="text-indigo-400" />
          <h2 className="text-sm font-semibold text-white">Discord Webhook</h2>
        </div>
        <p className="text-xs text-slate-500 mb-3">
          Alerts fire automatically on new <span className="text-orange-400">critical</span> and{' '}
          <span className="text-yellow-400">high</span> severity threats. Use the button below to
          verify your webhook is reachable.
        </p>
        <div className="flex items-center gap-3">
          <button
            onClick={handleTestAlert}
            disabled={testLoading}
            className="flex items-center gap-2 px-3 py-1.5 text-xs bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded transition-colors"
          >
            {testLoading ? <Loader2 size={12} className="animate-spin" /> : <Bell size={12} />}
            Send test alert
          </button>
          {testStatus && (
            <span className={`flex items-center gap-1 text-xs ${testStatus.ok ? 'text-green-400' : 'text-red-400'}`}>
              {testStatus.ok ? <CheckCircle size={12} /> : <XCircle size={12} />}
              {testStatus.detail}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}
