import { NavLink } from 'react-router-dom'

export default function Layout({ children }) {
  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span>SideRSP</span>
        </div>
        <nav className="sidebar-nav">
          <NavLink to="/" end>概览</NavLink>
          <NavLink to="/rules">规则管理</NavLink>
          <NavLink to="/status">统计信息</NavLink>
        </nav>
      </aside>
      <div className="main">
        {children}
      </div>
    </div>
  )
}
