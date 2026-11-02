import { faqItems } from "@/app/data/faq";

// Native <details> accordion; the same items feed the FAQPage JSON-LD on the
// home page.
export function FAQ() {
  return (
    <div className="faq">
      {faqItems.map((item) => (
        <details key={item.question} className="fq" name="faq">
          <summary>
            <span className="q">{item.question}</span>
            <span className="pm" aria-hidden="true" />
          </summary>
          <div className="a">
            <p>{item.answer}</p>
          </div>
        </details>
      ))}
    </div>
  );
}
