import { useState, useEffect } from 'react'
import { X, Settings, Database, Cloud, Zap, Loader2, Save } from 'lucide-react'
import { useMeshStore } from '@/store/useMeshStore'
import { useApi } from '@/hooks/useApi'

export function SettingsModal() {
  const { isSettingsOpen, setSettingsOpen } = useMeshStore()
  const api = useApi()

  const [provider, setProvider] = useState<'azure' | 'openai' | 'lm_studio'>('azure')
  const [baseUrl, setBaseUrl] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [model, setModel] = useState('')

  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)

  // Fetch current settings on open
  useEffect(() => {
    if (isSettingsOpen) {
      api.get('/api/settings/llm').then((res: any) => {
        setProvider(res.provider || 'azure')
        setBaseUrl(res.base_url || '')
        setApiKey(res.api_key || '')
        setModel(res.model || '')
      }).catch(err => console.error("Failed to fetch settings", err))
    }
  }, [isSettingsOpen])

  if (!isSettingsOpen) return null

  const handleSave = async () => {
    setLoading(true)
    setSuccess(false)
    try {
      await api.post('/api/settings/llm', {
        provider,
        base_url: baseUrl,
        api_key: apiKey,
        model
      })
      setSuccess(true)
      setTimeout(() => {
        setSuccess(false)
        setSettingsOpen(false)
      }, 1500)
    } catch (err) {
      console.error("Failed to save settings", err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="glass-panel w-full max-w-lg overflow-hidden flex flex-col shadow-2xl border-mesh-border animate-in fade-in zoom-in-95 duration-200">

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-mesh-border bg-mesh-surface/50">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-mesh-accent/20 border border-mesh-accent/30 flex items-center justify-center">
              <Settings size={16} className="text-mesh-accent" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-mesh-text leading-tight">LLM Configuration</h2>
              <p className="text-xs text-mesh-text-dim">Configure the intelligence engine for the swarm</p>
            </div>
          </div>
          <button onClick={() => setSettingsOpen(false)} className="text-mesh-text-dim hover:text-mesh-text transition-colors">
            <X size={20} />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 flex flex-col gap-6">

          {/* Provider Selection */}
          <div className="flex flex-col gap-2">
            <label className="text-xs font-semibold text-mesh-text-dim uppercase tracking-wider">Provider</label>
            <div className="grid grid-cols-3 gap-2">
              <button
                onClick={() => setProvider('azure')}
                className={`flex flex-col items-center justify-center gap-2 p-3 rounded-lg border transition-all ${provider === 'azure' ? 'bg-mesh-accent/10 border-mesh-accent text-mesh-accent shadow-glow-accent' : 'bg-mesh-surface border-mesh-border text-mesh-text-dim hover:border-mesh-text/30'}`}
              >
                <Cloud size={20} />
                <span className="text-xs font-semibold">Azure</span>
              </button>

              <button
                onClick={() => setProvider('openai')}
                className={`flex flex-col items-center justify-center gap-2 p-3 rounded-lg border transition-all ${provider === 'openai' ? 'bg-mesh-accent/10 border-mesh-accent text-mesh-accent shadow-glow-accent' : 'bg-mesh-surface border-mesh-border text-mesh-text-dim hover:border-mesh-text/30'}`}
              >
                <Zap size={20} />
                <span className="text-xs font-semibold">OpenAI</span>
              </button>

              <button
                onClick={() => setProvider('lm_studio')}
                className={`flex flex-col items-center justify-center gap-2 p-3 rounded-lg border transition-all ${provider === 'lm_studio' ? 'bg-mesh-accent/10 border-mesh-accent text-mesh-accent shadow-glow-accent' : 'bg-mesh-surface border-mesh-border text-mesh-text-dim hover:border-mesh-text/30'}`}
              >
                <Database size={20} />
                <span className="text-xs font-semibold">LM Studio</span>
              </button>
            </div>
          </div>

          {/* Configuration Fields */}
          <div className="flex flex-col gap-4">

            {provider !== 'openai' && (
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-mesh-text-dim">
                  {provider === 'azure' ? 'Azure Endpoint URL' : 'Local Server Base URL'}
                </label>
                <input
                  type="text"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  placeholder={provider === 'lm_studio' ? 'http://localhost:1234/v1' : 'https://your-resource.openai.azure.com'}
                  className="w-full bg-black/40 border border-mesh-border rounded px-3 py-2 text-sm text-mesh-text focus:outline-none focus:border-mesh-accent transition-colors placeholder:text-mesh-text-dim/50"
                />
              </div>
            )}

            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-mesh-text-dim">
                {provider === 'lm_studio' ? 'API Key (Optional)' : 'API Key'}
              </label>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={provider === 'lm_studio' ? 'lm-studio' : 'sk-...'}
                className="w-full bg-black/40 border border-mesh-border rounded px-3 py-2 text-sm text-mesh-text focus:outline-none focus:border-mesh-accent transition-colors placeholder:text-mesh-text-dim/50"
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-mesh-text-dim">
                {provider === 'azure' ? 'Deployment Name' : 'Model Name'}
              </label>
              <input
                type="text"
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder={provider === 'azure' ? 'gpt-4o' : 'gpt-4o / local-model'}
                className="w-full bg-black/40 border border-mesh-border rounded px-3 py-2 text-sm text-mesh-text focus:outline-none focus:border-mesh-accent transition-colors placeholder:text-mesh-text-dim/50"
              />
            </div>

          </div>

          <div className="p-3 bg-mesh-warn/10 border border-mesh-warn/20 rounded-lg text-xs text-mesh-warn/90">
            <span className="font-bold">Note:</span> Changing these settings will terminate the current swarm and re-initialize all agents.
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-mesh-border bg-mesh-surface/30 flex justify-end gap-3">
          <button
            onClick={() => setSettingsOpen(false)}
            className="px-4 py-2 text-xs font-medium text-mesh-text-dim hover:text-mesh-text transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={loading || success}
            className={`px-4 py-2 rounded text-xs font-bold transition-all flex items-center gap-2 ${success ? 'bg-mesh-success text-black' : 'bg-mesh-accent text-white hover:bg-mesh-accent-2 shadow-glow-accent'}`}
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : success ? <Save size={14} /> : null}
            {success ? 'Saved!' : 'Save & Rebuild Swarm'}
          </button>
        </div>

      </div>
    </div>
  )
}
