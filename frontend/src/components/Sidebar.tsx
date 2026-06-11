import { NavLink } from 'react-router-dom'
import { LayoutDashboard, ShieldAlert, Users, Bell, Settings, Radio, Globe, LogOut } from 'lucide-react'

const PUBLIC_NAV = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/threats',   icon: ShieldAlert,     label: 'Threats'   },
  { to: '/map',       icon: Globe,           label: 'Map'       },
  { to: '/actors',    icon: Users,           label: 'Actors'    },
]

const ADMIN_NAV = [
  { to: '/admin/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/admin/threats',   icon: ShieldAlert,     label: 'Threats'   },
  { to: '/admin/map',       icon: Globe,           label: 'Map'       },
  { to: '/admin/actors',    icon: Users,           label: 'Actors'    },
  { to: '/admin/alerts',    icon: Bell,            label: 'Alerts'    },
  { to: '/admin/settings',  icon: Settings,        label: 'Settings'  },
]

interface Props {
  mode: 'public' | 'admin'
  onLogout?: () => void
}

export default function Sidebar({ mode, onLogout }: Props) {
  const nav = mode === 'admin' ? ADMIN_NAV : PUBLIC_NAV

  return (
    <aside className="w-56 shrink-0 bg-[#0d0d16] border-r border-[#1a1a28] flex flex-col">
      <div className="px-4 py-4 border-b border-[#1a1a28]">
        <div className="flex items-center gap-2">
          <Radio size={16} className="text-cyan-400" />
          <span className="font-bold text-white tracking-wider text-xs">CTI MONITOR</span>
        </div>
        <p className="text-[10px] text-slate-600 mt-1">Threat intelligence workspace</p>
      </div>

      <nav className="flex-1 p-2 space-y-1">
        {nav.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-2.5 px-3 py-2 text-xs border transition-colors ${
                isActive
                  ? 'border-cyan-500/50 bg-[#151526] text-white'
                  : 'border-transparent text-slate-500 hover:text-slate-200 hover:border-[#25253a] hover:bg-[#12121e]'
              }`
            }
          >
            <Icon size={14} />
            {label}
          </NavLink>
        ))}
      </nav>

      {mode === 'admin' && (
        <div className="p-2 border-t border-[#1a1a28]">
          <button
            onClick={onLogout}
            className="w-full flex items-center gap-2.5 px-3 py-2 text-xs border border-transparent text-slate-500 hover:text-slate-200 hover:border-[#25253a] hover:bg-[#12121e] transition-colors"
          >
            <LogOut size={14} />
            Logout
          </button>
        </div>
      )}
    </aside>
  )
}
