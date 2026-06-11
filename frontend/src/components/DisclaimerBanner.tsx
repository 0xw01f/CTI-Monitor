import { AlertTriangle } from 'lucide-react'

export default function DisclaimerBanner() {
  return (
    <div className="shrink-0 bg-amber-950/20 border-b border-amber-900/30 px-4 py-1.5">
      <p className="flex items-center justify-center gap-1.5 text-[10px] text-amber-400/80 text-center">
        <AlertTriangle size={10} className="shrink-0" />
        CTI Monitor relies on automated parsing and AI enrichment — data may contain errors,
        omissions, or incorrect classifications. Always verify before acting.
      </p>
    </div>
  )
}
