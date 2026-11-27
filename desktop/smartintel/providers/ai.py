"""Optional AI adapters. API keys are stored in the OS credential store."""
import os

def get_api_key(provider):
    import keyring
    return keyring.get_password('smart-intel',provider.lower())

def save_api_key(provider,key):
    import keyring
    keyring.set_password('smart-intel',provider.lower(),key.strip())

def delete_api_key(provider):
    import keyring
    try: keyring.delete_password('smart-intel',provider.lower())
    except keyring.errors.PasswordDeleteError: pass

def analyze(provider,prompt,evidence):
    key=get_api_key(provider)
    if not key: raise RuntimeError(f'No {provider} API key saved. Open AI provider settings.')
    context='\\n\\n'.join(f'[{i+1}] {e.title} | Source: {e.source} | URL: {e.url}\\n{e.content[:9000]}' for i,e in enumerate(evidence))
    task=('You are an OSINT analysis assistant. Analyze only supplied public-source evidence. Separate verified facts, inferences and unknowns. Never invent sources or facts. Cite evidence by [number], identify contradictions, explain confidence and limitations. Do not infer sensitive personal attributes. User task: '+prompt+'\\n\\nEVIDENCE:\\n'+context)
    if provider=='OpenAI':
        from openai import OpenAI
        return OpenAI(api_key=key).responses.create(model=os.getenv('SMART_INTEL_OPENAI_MODEL','gpt-4.1-mini'),input=task).output_text
    if provider=='Gemini':
        from google import genai
        return genai.Client(api_key=key).models.generate_content(model=os.getenv('SMART_INTEL_GEMINI_MODEL','gemini-2.5-flash'),contents=task).text
    if provider=='Claude':
        import anthropic
        c=anthropic.Anthropic(api_key=key)
        r=c.messages.create(model=os.getenv('SMART_INTEL_CLAUDE_MODEL','claude-3-7-sonnet-latest'),max_tokens=5000,messages=[{'role':'user','content':task}])
        return '\\n'.join(x.text for x in r.content if getattr(x,'type',None)=='text')
    raise ValueError('Unknown AI provider')
