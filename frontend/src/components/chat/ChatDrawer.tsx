"use client";

import React, { useState, useEffect } from "react";
import { X, Send, Bot, User, Sparkles, Shield, Terminal, Briefcase, Lock } from "lucide-react";

export type PersonaType = "Executive" | "Developer" | "Red Teamer";

interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  persona?: PersonaType;
  toolsUsed?: string[];
}

const renderInlineFormatting = (text: string) => {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`|\[CRITICAL\]|\[HIGH\]|\[MEDIUM\]|\[LOW\]|\*\*Critical\*\*|\*\*High\*\*|\*\*Medium\*\*|\*\*Low\*\*)/g);

  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      const inner = part.slice(2, -2);
      if (inner.toLowerCase() === "critical") {
        return <span key={i} className="inline-block px-1.5 py-0.5 mx-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/40 text-[9.5px] font-mono font-bold uppercase tracking-wider">CRITICAL</span>;
      }
      if (inner.toLowerCase() === "high") {
        return <span key={i} className="inline-block px-1.5 py-0.5 mx-0.5 rounded bg-[#ff5400]/20 text-[#ff5400] border border-[#ff5400]/40 text-[9.5px] font-mono font-bold uppercase tracking-wider">HIGH</span>;
      }
      if (inner.toLowerCase() === "medium") {
        return <span key={i} className="inline-block px-1.5 py-0.5 mx-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 text-[9.5px] font-mono font-bold uppercase tracking-wider">MEDIUM</span>;
      }
      if (inner.toLowerCase() === "low") {
        return <span key={i} className="inline-block px-1.5 py-0.5 mx-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/40 text-[9.5px] font-mono font-bold uppercase tracking-wider">LOW</span>;
      }
      return <strong key={i} className="font-semibold text-[#ffffff]">{inner}</strong>;
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code key={i} className="px-1.5 py-0.5 mx-0.5 rounded bg-[#181924] border border-white/10 font-mono text-[11px] text-[#ffb703] break-all">
          {part.slice(1, -1)}
        </code>
      );
    }
    if (part === "[CRITICAL]") {
      return <span key={i} className="inline-block px-1.5 py-0.5 mx-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/40 text-[9.5px] font-mono font-bold uppercase tracking-wider">CRITICAL</span>;
    }
    if (part === "[HIGH]") {
      return <span key={i} className="inline-block px-1.5 py-0.5 mx-0.5 rounded bg-[#ff5400]/20 text-[#ff5400] border border-[#ff5400]/40 text-[9.5px] font-mono font-bold uppercase tracking-wider">HIGH</span>;
    }
    if (part === "[MEDIUM]") {
      return <span key={i} className="inline-block px-1.5 py-0.5 mx-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 text-[9.5px] font-mono font-bold uppercase tracking-wider">MEDIUM</span>;
    }
    if (part === "[LOW]") {
      return <span key={i} className="inline-block px-1.5 py-0.5 mx-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/40 text-[9.5px] font-mono font-bold uppercase tracking-wider">LOW</span>;
    }
    return part;
  });
};

const FormattedChatMessage: React.FC<{ content: string }> = ({ content }) => {
  let cleanContent = content
    .replace(/【<<CONTEXT_START>>[\s\S]*?<<CONTEXT_END>>】/g, "")
    .replace(/<<CONTEXT_START>>[\s\S]*?<<CONTEXT_END>>/g, "")
    .trim();

  const blocks = cleanContent.split(/(```[\s\S]*?```)/g);

  return (
    <div className="space-y-3 text-xs leading-relaxed text-[#e1e1e6]">
      {blocks.map((block, idx) => {
        if (block.startsWith("```") && block.endsWith("```")) {
          const lines = block.slice(3, -3).trim().split("\n");
          const firstLine = lines[0].trim();
          const hasLang = /^[a-zA-Z0-9_-]+$/.test(firstLine);
          const lang = hasLang ? firstLine : "";
          const code = hasLang ? lines.slice(1).join("\n") : lines.join("\n");

          return (
            <div key={idx} className="my-2.5 rounded-lg border border-white/10 bg-[#07080b] overflow-hidden shadow-inner font-mono">
              {lang && (
                <div className="bg-[#12131a] px-3 py-1 border-b border-white/8 text-[10px] text-[#8e8e9a] font-bold uppercase tracking-wider flex justify-between items-center">
                  <span>{lang}</span>
                  <span className="text-[9px] text-[#ff5400]">REMEDIATION CODE</span>
                </div>
              )}
              <pre className="p-3 text-[11px] text-amber-300 overflow-x-auto whitespace-pre leading-normal">
                <code>{code}</code>
              </pre>
            </div>
          );
        }

        const lines = block.split("\n");
        return (
          <div key={idx} className="space-y-1.5">
            {lines.map((line, lineIdx) => {
              const trimmed = line.trim();
              if (!trimmed) return null;

              if (trimmed.startsWith("#")) {
                const headerText = trimmed.replace(/^#+\s*/, "");
                return (
                  <h4 key={lineIdx} className="text-[13px] font-bold text-[#f4f4f8] pt-2 pb-1 border-b border-white/8 font-mono flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#ff5400]" />
                    {renderInlineFormatting(headerText)}
                  </h4>
                );
              }

              if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
                const listText = trimmed.substring(2);
                return (
                  <div key={lineIdx} className="flex items-start gap-2 pl-1 my-0.5">
                    <span className="text-[#ff5400] text-[10px] mt-0.5 shrink-0">•</span>
                    <div className="flex-1">{renderInlineFormatting(listText)}</div>
                  </div>
                );
              }

              const numMatch = trimmed.match(/^(\d+)\.\s+(.*)/);
              if (numMatch) {
                return (
                  <div key={lineIdx} className="flex items-start gap-2 pl-1 my-1">
                    <span className="text-[#ff5400] font-mono text-[11px] font-bold shrink-0">{numMatch[1]}.</span>
                    <div className="flex-1">{renderInlineFormatting(numMatch[2])}</div>
                  </div>
                );
              }

              if (trimmed.startsWith("|") && trimmed.endsWith("|")) {
                if (trimmed.includes("---")) return null;
                const cells = trimmed.split("|").map((c) => c.trim()).filter(Boolean);
                return (
                  <div key={lineIdx} className="my-1.5 p-2 rounded-lg bg-[#12131a] border border-white/8 flex flex-wrap gap-3 text-[11px]">
                    {cells.map((cell, cIdx) => (
                      <div key={cIdx} className="flex-1 min-w-[120px]">
                        {renderInlineFormatting(cell)}
                      </div>
                    ))}
                  </div>
                );
              }

              if (trimmed.startsWith("**Sources:**") || trimmed.startsWith("Sources:")) {
                return (
                  <div key={lineIdx} className="mt-3 pt-2 border-t border-white/10 text-[11px] font-mono text-[#8e8e9a]">
                    <span className="font-bold text-[#f4f4f8]">📌 Evidence Sources:</span>
                  </div>
                );
              }

              return <p key={lineIdx} className="leading-relaxed">{renderInlineFormatting(trimmed)}</p>;
            })}
          </div>
        );
      })}
    </div>
  );
};

interface ChatDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  initialContext?: string;
  report?: any;
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export const ChatDrawer: React.FC<ChatDrawerProps> = ({
  isOpen,
  onClose,
  initialContext = "",
  report,
}) => {
  const [persona, setPersona] = useState<PersonaType>("Developer");
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "1",
      role: "assistant",
      content: `Hello! I am your AI Code Guardian Assistant tailored for the **${persona}** persona. How can I assist you with security findings or code analysis today?`,
      persona: persona,
    },
  ]);
  const [input, setInput] = useState(initialContext ? `Tell me more about finding: ${initialContext}` : "");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (initialContext) {
      setInput(`Tell me more about finding: ${initialContext}`);
    }
  }, [initialContext, isOpen]);

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMsg: ChatMessage = {
      id: Date.now().toString(),
      role: "user",
      content: input,
      persona: persona,
    };

    setMessages((prev) => [...prev, userMsg]);
    const currentInput = input;
    setInput("");
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE}/api/v1/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: [...messages, userMsg].map((msg) => ({
            role: msg.role,
            content: msg.content,
          })),
          persona: persona,
          temperature: 0.2,
          report: report || null,
        }),
      });

      if (!response.ok) throw new Error("Chat request failed");
      const data = await response.json();

      const assistantMsg: ChatMessage = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: data.reply || "Analysis completed.",
        persona: data.persona || persona,
        toolsUsed: data.tools_used || [],
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          id: (Date.now() + 1).toString(),
          role: "assistant",
          content: "Sorry, an error occurred while connecting to the AI reasoning service.",
          persona: persona,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const getPersonaIcon = (p: PersonaType) => {
    if (p === "Executive") return <Briefcase className="w-3.5 h-3.5 text-[#ff5400]" />;
    if (p === "Developer") return <Terminal className="w-3.5 h-3.5 text-[#ff5400]" />;
    return <Shield className="w-3.5 h-3.5 text-[#ff5400]" />;
  };

  return (
    <div
      onClick={onClose}
      className={`fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-md flex justify-end transition-opacity duration-300 ease-in-out ${
        isOpen ? "opacity-100 pointer-events-auto" : "opacity-0 pointer-events-none"
      }`}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className={`w-full max-w-xl bg-[#0c0d11] border-l border-white/8 text-[#f4f4f8] h-full flex flex-col shadow-[-20px_0_60px_rgba(0,0,0,0.7)] transform transition-transform duration-300 ease-[cubic-bezier(0.16,1,0.3,1)] ${
          isOpen ? "translate-x-0" : "translate-x-full"
        }`}
      >

        {/* Header */}
        <div className="p-4 border-b border-white/8 flex items-center justify-between bg-[#12131a]">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-[#0c0d11] border border-[#ff5400]/30 flex items-center justify-center">
              <Bot className="w-5 h-5 text-[#ff5400]" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-[#f4f4f8] font-mono tracking-wide flex items-center gap-1.5">
                AI GUARDIAN CHAT
              </h2>
              <p className="text-[11px] font-mono text-[#8e8e9a]">Contextual Reasoning & Persona Guidance</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Persona Selector */}
            <div className="flex items-center gap-1.5 bg-[#0c0d11] border border-white/10 rounded-lg px-2.5 py-1.5 hover:border-[#ff5400]/30 transition-colors">
              {getPersonaIcon(persona)}
              <select
                value={persona}
                onChange={(e) => setPersona(e.target.value as PersonaType)}
                className="bg-transparent text-xs font-mono font-semibold text-[#f4f4f8] focus:outline-none cursor-pointer"
              >
                <option value="Executive" className="bg-[#0c0d11]">Executive</option>
                <option value="Developer" className="bg-[#0c0d11]">Developer</option>
                <option value="Red Teamer" className="bg-[#0c0d11]">Red Teamer</option>
              </select>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-[#8e8e9a] hover:text-[#f4f4f8] hover:bg-white/8 transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Message Thread */}
        <div className="p-4 flex-1 overflow-y-auto space-y-4 bg-[#0B0F19]">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
            >
              {msg.role === "assistant" && (
                <div className="w-8 h-8 rounded-full bg-[#12131a] border border-[#ff5400]/20 flex items-center justify-center shrink-0">
                  <Bot className="w-4 h-4 text-[#ff5400]" />
                </div>
              )}
              <div
                className={`max-w-[85%] rounded-xl p-3.5 text-xs leading-relaxed space-y-2 ${
                  msg.role === "user"
                    ? "bg-[#ff5400] text-black font-semibold rounded-tr-none"
                    : "bg-[#12131a] border border-white/8 text-[#f4f4f8] rounded-tl-none"
                }`}
              >
                {msg.role === "user" ? (
                  <div className="whitespace-pre-wrap">{msg.content}</div>
                ) : (
                  <FormattedChatMessage content={msg.content} />
                )}
              </div>
              {msg.role === "user" && (
                <div className="w-8 h-8 rounded-full bg-[#ff5400]/10 border border-[#ff5400]/30 flex items-center justify-center shrink-0">
                  <User className="w-4 h-4 text-[#ff5400]" />
                </div>
              )}
            </div>
          ))}
          {loading && (
            <div className="flex gap-3 justify-start items-center text-xs font-mono text-[#8e8e9a] animate-pulse">
              <Bot className="w-4 h-4 text-[#ff5400]" />
              <span>NEMOTRON REASONING IN PROGRESS...</span>
            </div>
          )}
        </div>

        {/* Input Footer */}
        <form
          onSubmit={handleSendMessage}
          className="p-4 border-t border-white/8 bg-[#12131a] flex gap-2"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={`Ask in ${persona} persona...`}
            className="flex-1 glass-input rounded-lg px-4 py-2.5 text-xs font-mono focus:outline-none transition"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="px-4 py-2.5 rounded-lg glass-button disabled:opacity-40 transition flex items-center gap-1.5 text-xs font-mono font-bold"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>

      </div>
    </div>
  );
};

export default ChatDrawer;
