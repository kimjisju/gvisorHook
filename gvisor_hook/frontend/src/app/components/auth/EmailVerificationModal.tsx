import { motion, AnimatePresence } from "motion/react";
import { X, Mail, CheckCircle } from "lucide-react";

interface EmailVerificationModalProps {
  isOpen: boolean;
  onClose: () => void;
  email: string;
  verifyUrl?: string;
  onSwitchToLogin: () => void;
}

export function EmailVerificationModal({
  isOpen,
  onClose,
  email,
  verifyUrl,
  onSwitchToLogin,
}: EmailVerificationModalProps) {
  const handleResendEmail = () => {
    // UI only - no actual functionality
    console.log("Resend email to:", email);
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50"
          />

          {/* Modal */}
          <div className="fixed inset-0 flex items-center justify-center z-50 p-4">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              transition={{ duration: 0.2 }}
              className="bg-white rounded-2xl shadow-2xl w-full max-w-md overflow-hidden"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header */}
              <div className="bg-gradient-to-r from-blue-600 to-cyan-600 px-6 py-4 flex items-center justify-between">
                <h2 className="font-display font-bold text-xl text-white">이메일 인증</h2>
                <button
                  onClick={onClose}
                  className="p-1 hover:bg-white/20 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5 text-white" />
                </button>
              </div>

              {/* Body */}
              <div className="p-8 text-center space-y-6">
                {/* Icon */}
                <div className="flex justify-center">
                  <div className="relative">
                    <div className="w-24 h-24 bg-gradient-to-br from-blue-100 to-cyan-100 rounded-full flex items-center justify-center">
                      <Mail className="w-12 h-12 text-blue-600" />
                    </div>
                    <div className="absolute -bottom-1 -right-1 w-8 h-8 bg-green-500 rounded-full flex items-center justify-center border-4 border-white">
                      <CheckCircle className="w-5 h-5 text-white" />
                    </div>
                  </div>
                </div>

                {/* Title */}
                <div className="space-y-2">
                  <h3 className="font-display font-bold text-2xl text-slate-900">
                    인증 링크를 메일로 전송했습니다
                  </h3>
                  <p className="text-slate-600 leading-relaxed">
                    이메일로 전송 받은 인증 링크를 확인해 주세요.
                    <br />
                    링크는 발송 시점으로부터 24시간 동안 유효합니다.
                  </p>
                </div>

                {/* Email Display */}
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                  <div className="flex items-center justify-center gap-2">
                    <Mail className="w-5 h-5 text-slate-500" />
                    <span className="font-mono font-medium text-slate-900">{email}</span>
                  </div>
                </div>

                {verifyUrl && (
                  <a
                    href={verifyUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="block w-full rounded-xl border border-blue-200 bg-blue-50 px-4 py-3 text-sm font-semibold text-blue-700 hover:bg-blue-100"
                  >
                    개발 모드 인증 링크 열기
                  </a>
                )}

                {/* Login Button */}
                <button
                  onClick={onSwitchToLogin}
                  className="w-full py-3 bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-semibold rounded-xl hover:shadow-lg hover:scale-[1.02] active:scale-[0.98] transition-all duration-200"
                >
                  로그인
                </button>

                {/* Resend Link */}
                <div className="text-center pt-2">
                  <span className="text-sm text-slate-600">이메일을 받지 못하셨나요? </span>
                  <button
                    type="button"
                    onClick={handleResendEmail}
                    className="text-sm text-blue-600 hover:text-blue-700 font-semibold"
                  >
                    이메일 다시 보내기
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
}
