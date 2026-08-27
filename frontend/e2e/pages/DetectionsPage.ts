import { KronosPage } from "./KronosPage";
import { DetectionDetailPage } from "./DetectionDetailPage";

/** Real, authenticated `/detections` list view. */
export class DetectionsPage extends KronosPage {
  async waitUntilReady(): Promise<void> {
    await this.page.waitForURL("**/detections", { timeout: 10000 });
  }

  /** Opens a real detection row by its (assumed-unique) real rule name. */
  async openDetectionByRuleName(ruleName: string): Promise<DetectionDetailPage> {
    await this.page.locator(`a:has-text('${ruleName}')`).click();
    const detail = new DetectionDetailPage(this.page);
    await detail.waitUntilReady();
    return detail;
  }
}
