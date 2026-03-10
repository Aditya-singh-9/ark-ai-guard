import LandingNavbar from "@/components/landing/LandingNavbar";
import HeroSection from "@/components/landing/HeroSection";
import FeaturesSection from "@/components/landing/FeaturesSection";
import HowItWorksSection from "@/components/landing/HowItWorksSection";
import PlatformPreview from "@/components/landing/PlatformPreview";
import TrustSection from "@/components/landing/TrustSection";
import Footer from "@/components/landing/Footer";

const Index = () => (
  <div className="min-h-screen bg-background">
    <LandingNavbar />
    <HeroSection />
    <div id="features"><FeaturesSection /></div>
    <div id="how-it-works"><HowItWorksSection /></div>
    <div id="preview"><PlatformPreview /></div>
    <TrustSection />
    <Footer />
  </div>
);

export default Index;
