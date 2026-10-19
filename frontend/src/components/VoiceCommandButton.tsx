import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  useVoiceCommands,
  type UseVoiceCommandsResult,
  type VoiceCommand,
} from "../hooks/useVoiceCommands";

export interface VoiceCommandButtonProps {
  voice?: UseVoiceCommandsResult;
  commands?: VoiceCommand[];
  className?: string;
  showHelp?: boolean;
}

export const VoiceCommandButton: React.FC<VoiceCommandButtonProps> = ({
  voice: voiceProp,
  commands,
  className = "",
}) => {
  const { t } = useTranslation();
  const internalVoice = useVoiceCommands({ commands });
  const voice = voiceProp ?? internalVoice;

  const [showTooltip, setShowTooltip] = useState(false);

  const {
    isSupported,
    isListening,
    permissionState,
    interimTranscript,
    lastMatch,
    error,
    toggle,
    requestPermission,
  } = voice;

  const handleClick = async () => {
    if (permissionState === "denied") {
      setShowTooltip(true);
      return;
    }
    await toggle();
  };

  const getLabel = () => {
    if (!isSupported) {
      return t("voice.unavailable", { defaultValue: "Voice commands not supported" });
    }
    if (permissionState === "denied") {
      return t("voice.permissionDenied", {
        defaultValue: "Microphone access denied. Click to learn more.",
      });
    }
    if (isListening) {
      return t("voice.listening", { defaultValue: "Listening… Click to stop" });
    }
    return t("voice.startListening", { defaultValue: "Start voice commands" });
  };

  return (
    <div
      style={{
        position: "relative",
        display: "inline-flex",
        alignItems: "center",
      }}
    >
      <button
        type="button"
        className={`voice-toggle ${className}`.trim()}
        onClick={handleClick}
        disabled={!isSupported}
        aria-pressed={isListening}
        aria-label={getLabel()}
        title={getLabel()}
        onMouseEnter={() => setShowTooltip(true)}
        onMouseLeave={() => setShowTooltip(false)}
      >
        {isListening ? (
          <span className="voice-indicator" aria-hidden="true" />
        ) : (
          <svg
            width="18"
            height="18"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z" />
            <path d="M19 10v2a7 7 0 0 1-14 0v-2" />
            <line x1="12" x2="12" y1="19" y2="22" />
          </svg>
        )}
        <span style={{ fontSize: "0.85rem", fontWeight: 500 }}>
          {isListening
            ? t("voice.listening", { defaultValue: "Listening…" })
            : t("voice.title", { defaultValue: "Voice" })}
        </span>
      </button>

      {/* Real-time transcript visual feedback */}
      {isListening && interimTranscript && (
        <div
          role="status"
          aria-live="polite"
          style={{
            position: "absolute",
            top: "calc(100% + 8px)",
            right: 0,
            zIndex: 1000,
            padding: "0.5rem 0.75rem",
            background: "var(--bg-card, #1e293b)",
            color: "var(--text-primary, #f8fafc)",
            border: "1px solid var(--border-color, #334155)",
            borderRadius: "0.5rem",
            fontSize: "0.8rem",
            whiteSpace: "nowrap",
            boxShadow: "0 4px 12px rgba(0, 0, 0, 0.2)",
          }}
        >
          <em>"{interimTranscript}"</em>
        </div>
      )}

      {/* Last matched command feedback */}
      {lastMatch && (
        <div
          role="status"
          aria-live="polite"
          style={{
            position: "absolute",
            top: "calc(100% + 8px)",
            right: 0,
            zIndex: 999,
            padding: "0.4rem 0.6rem",
            background: "var(--bg-card, #065f46)",
            color: "#ecfdf5",
            border: "1px solid #10b981",
            borderRadius: "0.375rem",
            fontSize: "0.75rem",
            whiteSpace: "nowrap",
          }}
        >
          ✓ {lastMatch.action}: {lastMatch.phrase}
        </div>
      )}

      {/* Permission denied helper popup */}
      {showTooltip && permissionState === "denied" && (
        <div
          className="voice-permission-denied"
          style={{
            position: "absolute",
            top: "calc(100% + 8px)",
            right: 0,
            zIndex: 1000,
            minWidth: "260px",
            boxShadow: "0 4px 14px rgba(0, 0, 0, 0.15)",
          }}
        >
          <div>
            <strong>{t("voice.permissionTitle", { defaultValue: "Microphone Access" })}</strong>
            <p style={{ margin: "0.25rem 0" }}>
              {t("voice.permissionDenied", {
                defaultValue:
                  "Microphone access was denied. Please allow microphone access in your browser settings to use voice commands.",
              })}
            </p>
            <button
              type="button"
              onClick={() => void requestPermission()}
              style={{
                marginTop: "0.25rem",
                padding: "0.25rem 0.5rem",
                fontSize: "0.75rem",
                cursor: "pointer",
              }}
            >
              {t("voice.permissionRequest", { defaultValue: "Retry Permission" })}
            </button>
          </div>
        </div>
      )}

      {/* Error notification */}
      {error && error !== "not-allowed" && (
        <div
          role="alert"
          style={{
            position: "absolute",
            top: "calc(100% + 8px)",
            right: 0,
            zIndex: 1000,
            padding: "0.4rem 0.6rem",
            background: "var(--bg-card, #7f1d1d)",
            color: "#fef2f2",
            border: "1px solid #ef4444",
            borderRadius: "0.375rem",
            fontSize: "0.75rem",
            whiteSpace: "nowrap",
          }}
        >
          {error}
        </div>
      )}
    </div>
  );
};

export default VoiceCommandButton;
