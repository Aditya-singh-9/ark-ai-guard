/**
 * useApi — centralized hook for API calls with:
 *   - Loading / error state management
 *   - Automatic toast on error
 *   - Abort-on-unmount cleanup
 */
import { useState, useCallback, useRef, useEffect } from "react";
import { toast } from "sonner";

interface ApiState<T> {
  data: T | null;
  isLoading: boolean;
  error: string | null;
}

interface UseApiOptions {
  showErrorToast?: boolean;
  errorPrefix?: string;
}

export function useApi<T>(
  apiFn: () => Promise<T>,
  options: UseApiOptions = {}
): ApiState<T> & { refetch: () => void } {
  const { showErrorToast = true, errorPrefix = "" } = options;
  const [state, setState] = useState<ApiState<T>>({
    data: null,
    isLoading: true,
    error: null,
  });
  const abortRef = useRef(false);

  const fetch = useCallback(async () => {
    abortRef.current = false;
    setState((s) => ({ ...s, isLoading: true, error: null }));
    try {
      const data = await apiFn();
      if (!abortRef.current) setState({ data, isLoading: false, error: null });
    } catch (err: any) {
      if (abortRef.current) return;
      const msg = err?.message ?? "Unknown error";
      setState({ data: null, isLoading: false, error: msg });
      if (showErrorToast) toast.error(`${errorPrefix}${msg}`);
    }
  }, [apiFn, showErrorToast, errorPrefix]);

  useEffect(() => {
    fetch();
    return () => { abortRef.current = true; };
  }, [fetch]);

  return { ...state, refetch: fetch };
}
