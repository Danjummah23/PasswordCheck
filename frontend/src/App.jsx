import { useState } from 'react'
import './App.css'

const SCORE_CONFIG = {
  'VERY WEAK': { color: '#ef4444', bg: '#fef2f2', bar: 10 },
  'WEAK':      { color: '#f97316', bg: '#fff7ed', bar: 28 },
  'FAIR':      { color: '#eab308', bg: '#fefce8', bar: 52 },
  'GOOD':      { color: '#22c55e', bg: '#f0fdf4', bar: 76 },
  'STRONG':    { color: '#10b981', bg: '#ecfdf5', bar: 100 },
}

function ScoreBar({ score }) {
  const cfg = SCORE_CONFIG[score] ?? SCORE_CONFIG['FAIR']
  return (
    <div className="bar-track">
      <div className="bar-fill" style={{ width: `${cfg.bar}%`, background: cfg.color }} />
    </div>
  )
}

function CheckRow({ check }) {
  const icon = check.passed ? '✓' : check.severity === 'critical' ? '✗' : '!'
  return (
    <div className={`check-row ${check.passed ? 'pass' : check.severity}`}>
      <span className="check-icon">{icon}</span>
      <div className="check-text">
        <span className="check-name">{check.name}</span>
        <span className="check-msg">{check.message}</span>
      </div>
    </div>
  )
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1600)
    })
  }
  return (
    <button className="copy-btn" onClick={copy}>
      {copied ? '✓ Copied' : 'Copy'}
    </button>
  )
}

export default function App() {
  const [password, setPassword] = useState('')
  const [showPw,   setShowPw]   = useState(false)
  const [noHibp,   setNoHibp]   = useState(false)
  const [result,   setResult]   = useState(null)
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState(null)

  async function handleCheck(e) {
    e.preventDefault()
    if (!password) return
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('http://localhost:5000/api/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password, no_hibp: noHibp }),
      })
      if (!res.ok) throw new Error()
      setResult(await res.json())
    } catch {
      setError('Cannot reach the Python API. Make sure api.py is running on port 5000.')
    } finally {
      setLoading(false)
    }
  }

  function handleChange(e) {
    setPassword(e.target.value)
    setResult(null)
    setError(null)
  }

  const cfg = result ? SCORE_CONFIG[result.score] : null

  return (
    <div className="app">
      <header className="header">
        <div className="header-icon">🔐</div>
        <h1>Password Vulnerability Checker</h1>
        <p className="subtitle">Detect weak patterns and check breach exposure</p>
      </header>

      <form className="card" onSubmit={handleCheck}>
        <label className="field-label">Password</label>
        <div className="input-row">
          <input
            type={showPw ? 'text' : 'password'}
            value={password}
            onChange={handleChange}
            placeholder="Enter a password to analyse…"
            className="pw-input"
            autoComplete="off"
            spellCheck={false}
          />
          <button type="button" className="eye-btn" onClick={() => setShowPw(v => !v)}
            title={showPw ? 'Hide password' : 'Show password'}>
            {showPw ? '🙈' : '👁️'}
          </button>
        </div>

        <label className="toggle-label">
          <input type="checkbox" checked={noHibp} onChange={e => setNoHibp(e.target.checked)} />
          Offline mode — skip Have I Been Pwned breach check
        </label>

        <button type="submit" className="check-btn" disabled={loading || !password}>
          {loading && <span className="spinner" />}
          {loading ? 'Checking…' : 'Check Password'}
        </button>
      </form>

      {error && <div className="error-banner">{error}</div>}

      {result && (
        <div className="card result-card" style={{ borderTop: `4px solid ${cfg.color}` }}>

          <div className="score-section" style={{ background: cfg.bg }}>
            <div>
              <div className="score-label">Score</div>
              <div className="score-value" style={{ color: cfg.color }}>{result.score}</div>
            </div>
            <div className="meta-group">
              <div className="meta-item">
                <span className="meta-label">Entropy</span>
                <span className="meta-value">{result.entropy_bits} bits</span>
              </div>
              <div className="meta-divider" />
              <div className="meta-item">
                <span className="meta-label">Crack time</span>
                <span className="meta-value">{result.crack_time}</span>
              </div>
            </div>
          </div>

          <ScoreBar score={result.score} />

          <div className="checks-list">
            {result.checks.map(c => <CheckRow key={c.name} check={c} />)}
          </div>

          <div className="tally">
            <span className="tally-item critical">{result.critical_count} critical</span>
            <span className="tally-item warning">
              {result.warning_count} warning{result.warning_count !== 1 ? 's' : ''}
            </span>
          </div>

          {result.suggestion && (
            <div className="suggestion">
              <span className="suggestion-label">Suggested strong password</span>
              <div className="suggestion-row">
                <code className="suggestion-code">{result.suggestion}</code>
                <CopyButton text={result.suggestion} />
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
