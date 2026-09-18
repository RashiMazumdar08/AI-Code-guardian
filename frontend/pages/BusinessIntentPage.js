import "../src/app/globals.css";
import BusinessIntentPage from "../src/components/intent/BusinessIntentPage";

export default function Page(props) {
  return (
    <div className="bg-[#0B0F19] text-[#f4f4f8] min-h-screen p-6">
      <BusinessIntentPage {...props} />
    </div>
  );
}
