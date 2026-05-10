import { motion } from "framer-motion";
import { ReactNode } from "react";

interface PageTransitionProps {
  children: ReactNode;
  className?: string;
}

/**
 * PageTransition — wraps each dashboard page in a smooth
 * fade + slide-up animation. Use as the outermost wrapper
 * of any page component.
 */
const PageTransition = ({ children, className = "" }: PageTransitionProps) => (
  <motion.div
    initial={{ opacity: 0, y: 12 }}
    animate={{ opacity: 1, y: 0 }}
    exit={{ opacity: 0, y: -6 }}
    transition={{
      duration: 0.28,
      ease: [0.22, 1, 0.36, 1], // custom cubic-bezier for snappy but smooth feel
    }}
    className={className}
    style={{ willChange: "opacity, transform" }}
  >
    {children}
  </motion.div>
);

export default PageTransition;
