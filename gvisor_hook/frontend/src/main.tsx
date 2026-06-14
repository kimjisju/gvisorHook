import { createRoot } from "react-dom/client";
import App from "./app/App";
import "./styles/index.css";

const DESKTOP_NOTIFICATION_PARAM = "argus_notification";

function suppressDuplicateApprovalModal() {
  const params = new URLSearchParams(window.location.search);
  if (params.get(DESKTOP_NOTIFICATION_PARAM) !== "desktop") return;

  const removeModal = () => {
    for (const element of document.querySelectorAll<HTMLElement>("body *")) {
      const text = element.textContent || "";
      if (
        !text.includes("사용자 승인이 필요합니다") ||
        !text.includes("승인") ||
        !text.includes("거절")
      ) {
        continue;
      }

      let overlay: HTMLElement | null = element;
      while (
        overlay &&
        !(overlay.classList.contains("fixed") && overlay.classList.contains("inset-0"))
      ) {
        overlay = overlay.parentElement;
      }
      if (!overlay) continue;

      const previous = overlay.previousElementSibling;
      if (
        previous instanceof HTMLElement &&
        previous.classList.contains("fixed") &&
        previous.classList.contains("inset-0")
      ) {
        previous.remove();
      }
      overlay.remove();
      break;
    }
  };

  const observer = new MutationObserver(removeModal);
  observer.observe(document.body, { childList: true, subtree: true });
  removeModal();
}

suppressDuplicateApprovalModal();
createRoot(document.getElementById("root")!).render(<App />);
