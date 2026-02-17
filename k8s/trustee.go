package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	redis "policy-agent/database"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/util/retry"
)

type ReferenceValue struct {
    Name       string   `json:"name"`
    Value      []string `json:"value"`
    Expiration string   `json:"expiration,omitempty"`
}

/**
 * Store session data (secretKey) in Trustee cluster as a k8s secret
 * Also update KbsConfig CR to reference the new secret
 */
func StoreSessionInTrustee(clients *Clients, ctx context.Context, session redis.SessionData) error {
	kbsNamespace := os.Getenv("KBS_NAMESPACE")
	if kbsNamespace == "" {
		kbsNamespace = "operators"
	}
	
	secretName := "pa-sessions"
	keyName := session.ID
	if len(session.SecretKey) == 0 {
		return fmt.Errorf("secretKey is empty")
	}

	secrets := clients.Local.CoreV1().Secrets(kbsNamespace)

	// --- Secret creation / update (with retry on resource version conflicts) ---
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		existing, err := secrets.Get(ctx, secretName, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			// Create new k8s secret
			sec := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: kbsNamespace,
					Labels: map[string]string{
						"app":  "policy-agent",
						"type": "session",
					},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					keyName: session.SecretKey,
				},
			}
			_, err = secrets.Create(ctx, sec, metav1.CreateOptions{})
			if err == nil {
				log.Printf("✅ created secret %s/%s with key %q", kbsNamespace, secretName, keyName)
			}
			return err
		}
		if err != nil {
			return err
		}

		// Update: add new key to existing k8s secret
		if existing.Data == nil {
			existing.Data = map[string][]byte{}
		}
		existing.Data[keyName] = session.SecretKey

		_, err = secrets.Update(ctx, existing, metav1.UpdateOptions{})
		if err == nil {
			log.Printf("🔄 upserted key %q in secret %s/%s", keyName, kbsNamespace, secretName)
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("write secret %s/%s: %w", kbsNamespace, secretName, err)
	}

	// --- KbsConfig (CR) update  ---
	kbsCfgName := os.Getenv("KBS_CONFIG_NAME")
	if kbsCfgName == "" {
		kbsCfgName = "kbsconfig-sample"
	}
	// Create dynamic client for updates custom resources
	dyn, err := dynamic.NewForConfig(clients.LocalCfg)
	if err != nil {
		return fmt.Errorf("dynamic client: %w", err)
	}
	gvr := schema.GroupVersionResource{
		Group:    "confidentialcontainers.org",
		Version:  "v1alpha1",
		Resource: "kbsconfigs",
	}
	
	u, err := dyn.Resource(gvr).Namespace(kbsNamespace).Get(ctx, kbsCfgName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get KbsConfig %s/%s: %w", kbsNamespace, kbsCfgName, err)
	}

	list, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "kbsSecretResources")
	already := false
	for _, name := range list {
		if name == secretName {
			already = true
			break
		}
	}
	if !already {
		list = append(list, secretName)
		if err := unstructured.SetNestedStringSlice(u.Object, list, "spec", "kbsSecretResources"); err != nil {
			return fmt.Errorf("set kbsSecretResources: %w", err)
		}
		if _, err := dyn.Resource(gvr).Namespace(kbsNamespace).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update KbsConfig %s/%s: %w", kbsNamespace, kbsCfgName, err)
		}
		log.Printf("✅ registered secret %q in KbsConfig %s/%s", secretName, kbsNamespace, kbsCfgName)
	}

	return nil
}

/**
* DeleteTrusteeSession removes the session data for the given session from the Trustee cluster.
* It deletes the corresponding key from the k8s secret and, if the secret becomes empty, deletes the secret itself.
* If the secret is deleted, it also updates the KbsConfig CR to remove the reference to the deleted secret.
*/
func DeleteTrusteeSession(clients *Clients, session redis.SessionData) error {
	kbsNamespace := os.Getenv("KBS_NAMESPACE")
	if kbsNamespace == "" {
		kbsNamespace = "operators"
	}

	secretName := "pa-sessions"
	keyName := session.ID

	ctx := context.TODO()
	secrets := clients.Local.CoreV1().Secrets(kbsNamespace)
	// Flag, if we completely delete the secret (and clean up KbsConfig afterwards)
	deletedSecret := false

	// --- Secret-Key deletion (with Retry on conflict) ---
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		existing, err := secrets.Get(ctx, secretName, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			// Secret does not exist -> later KbsConfig might be cleaned up anyway
			return nil
		}
		if err != nil {
			return err
		}

		if existing.Data == nil {
			return nil // Nothing to do
		}
		if _, ok := existing.Data[keyName]; !ok {
			return nil // Specific key does not exist -> nothing to do
		}

		// Delete key
		delete(existing.Data, keyName)

		// If no keys left: delete secret
		if len(existing.Data) == 0 {
			if err := secrets.Delete(ctx, secretName, metav1.DeleteOptions{}); err != nil {
				return fmt.Errorf("🗑️ delete empty secret %s/%s: %w", kbsNamespace, secretName, err)
			}
			deletedSecret = true
			log.Printf("🗑️ deleted empty secret %s/%s", kbsNamespace, secretName)
			return nil
		}

		// Otherwise update secret
		if _, err := secrets.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update secret %s/%s: %w", kbsNamespace, secretName, err)
		}
		log.Printf("🗑️ removed key %q from secret %s/%s", keyName, kbsNamespace, secretName)
		return nil
	})
	if err != nil {
		return fmt.Errorf("edit secret %s/%s: %w", kbsNamespace, secretName, err)
	}
	// --- KbsConfig (CR) update  ---
	// Only if the secret was completely deleted, remove the entry from kbsSecretResources.
	// (If the secret still contains other sessions, the reference remains sensible.)
	kbsCfgName := os.Getenv("KBS_CONFIG_NAME")
	if kbsCfgName == "" {
		kbsCfgName = "kbsconfig-sample"
	}

	if deletedSecret {
		dyn, err := dynamic.NewForConfig(clients.LocalCfg)
		if err != nil {
			return fmt.Errorf("dynamic client: %w", err)
		}
		gvr := schema.GroupVersionResource{
			Group:    "confidentialcontainers.org",
			Version:  "v1alpha1",
			Resource: "kbsconfigs",
		}

		u, err := dyn.Resource(gvr).Namespace(kbsNamespace).Get(ctx, kbsCfgName, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			// KbsConfig not found -> nothing to do
			return nil
		}
		if err != nil {
			return fmt.Errorf("get KbsConfig %s/%s: %w", kbsNamespace, kbsCfgName, err)
		}

		list, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "kbsSecretResources")
		// Remove secretName from the list (if present)
		newList := make([]string, 0, len(list))
		for _, name := range list {
			if name != secretName {
				newList = append(newList, name)
			}
		}
		// Only update if something changed
		if len(newList) != len(list) {
			if err := unstructured.SetNestedStringSlice(u.Object, newList, "spec", "kbsSecretResources"); err != nil {
				return fmt.Errorf("set kbsSecretResources: %w", err)
			}
			if _, err := dyn.Resource(gvr).Namespace(kbsNamespace).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("update KbsConfig %s/%s: %w", kbsNamespace, kbsCfgName, err)
			}
			log.Printf("🗑️ removed secret %q from KbsConfig %s/%s", secretName, kbsNamespace, kbsCfgName)
		}
	}
	return nil
}

/** 
* UpdateReferenceValues updates the "mr_config_id" entry inside the
* rvps-reference-values ConfigMap by removing the given oldMrConfigId
* and adding a new config_mr value.
*
* It expects the ConfigMap data["reference-values.json"] to be a JSON
* array of ReferenceValue objects (matching the Trustee format).
*/
func UpdateReferenceValues(clients *Clients, newMrConfigId, oldMrConfigId string) error {
	ctx := context.Background()
	if newMrConfigId == "" {
		return fmt.Errorf("newMrConfigId is empty")
	}
	if oldMrConfigId == "" {
		return fmt.Errorf("oldMrConfigId is empty")
	}

	rvpsNamespace := os.Getenv("KBS_NAMESPACE")
	if rvpsNamespace == "" {
		rvpsNamespace = "operators"
	}
	configMapName := os.Getenv("RVPS_CONFIGMAP_NAME")
	if configMapName == "" {
		configMapName = "rvps-reference-values"
	}

	configMapClient := clients.Local.CoreV1().ConfigMaps(rvpsNamespace)

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// Load current ConfigMap
		configMap, err := configMapClient.Get(ctx, configMapName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get ConfigMap %s/%s: %w", rvpsNamespace, configMapName, err)
		}

		raw, ok := configMap.Data["reference-values.json"]
		if !ok {
			return fmt.Errorf("key reference-values.json not found in ConfigMap %s/%s", rvpsNamespace, configMapName)
		}

		var list []ReferenceValue
		if err := json.Unmarshal([]byte(raw), &list); err != nil {
			return fmt.Errorf("unmarshal reference-values.json: %w", err)
		}

		foundMrConfigIdObj := false
		foundOld := false

		for i := range list {
			if list[i].Name != "mr_config_id" {
				continue
			}
			foundMrConfigIdObj = true

			// check if newMrConfigId is already present
			hasNew := false
			newSlice := make([]string, 0, len(list[i].Value))

			for _, value := range list[i].Value {
				// Drop entries with oldMrConfigId; keep everything else
				val := strings.ToLower(strings.TrimSpace(value))
				if val == oldMrConfigId {
					foundOld = true
					continue
				}
				if val == newMrConfigId {
					hasNew = true
				}
				newSlice = append(newSlice, val)
			}

			// Add the new mr_config_id value if it is not present yet
			if !hasNew {
				newSlice = append(newSlice, newMrConfigId)
			}

			list[i].Value = newSlice
		}

		if !foundMrConfigIdObj {
			return fmt.Errorf("no mr_config_id entry found in reference-values")
		}

		if !foundOld {
			// Explicitly signal that the given oldMrConfigId does not exist
			//log.Printf("⚠️  warning: oldMrConfigId not found in ConfigMap %s/%s", rvpsNamespace, configMapName)
			log.Printf("oldMrConfigId not found; old=%q (len=%d)", oldMrConfigId, len(oldMrConfigId))
			// NOTE: DEbugging output to find close matches in case of formatting issues (e.g. whitespace, case sensitivity)
			for _, refVal := range list {
				if refVal.Name != "mr_config_id" { continue }
				for _, value := range refVal.Value {
					if strings.Contains(value, oldMrConfigId) || strings.Contains(oldMrConfigId, value) {
						log.Printf("close match candidate: value=%q (len=%d)", value, len(value))
					}
				}
			}
			// NOTE: old value might not be present, so we do not error out here.
		}

		// Marshal back to JSON and update the ConfigMap
		newJSON, err := json.MarshalIndent(list, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal updated reference-values: %w", err)
		}
		if configMap.Data == nil {
			configMap.Data = map[string]string{}
		}
		configMap.Data["reference-values.json"] = string(newJSON)

		if _, err := configMapClient.Update(ctx, configMap, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("update ConfigMap %s/%s: %w", rvpsNamespace, configMapName, err)
		}

		log.Printf("✅ updated mr_config_id in ConfigMap %s/%s", rvpsNamespace, configMapName)
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

/**
* DeleteExpiredSessions removes expired sessions from the Trustee k8s secret.
* It takes a list of active session IDs to avoid deleting valid sessions.
*/
func DeleteExpiredSessions(clients *Clients, redisKeys []string) (error) {
	ctx := context.Background()
	ns := os.Getenv("KBS_NAMESPACE")
	if ns == "" {
		ns = "trustee-operator-system"
	}
	secretName := "pa-sessions"

	 // --- Set of active sessions ---
    active := make(map[string]struct{}, len(redisKeys))
    for _, id := range redisKeys {
		uuid := strings.TrimPrefix(id, "session:") // remove "session:" prefix if present
        active[uuid] = struct{}{}
    }

	secret, err := clients.Local.CoreV1().Secrets(ns).Get(
        ctx,
        secretName,
        metav1.GetOptions{},
    )
	// if secret does not exist, nothing to do
	if errors.IsNotFound(err) {
		log.Printf("No Trustee secret %s/%s found. Nothing to clean", ns, secretName)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get secret %s/%s: %w",
			ns, secretName, err)
	}
    changed := false

    // secret.Data ist map[string][]byte
    for key := range secret.Data {
        if _, ok := active[key]; !ok {
            log.Printf("🗑️ removing expired session from secret: %s", key)
            delete(secret.Data, key)
            changed = true
        }
    }

  if changed {
        _, err = clients.Local.CoreV1().Secrets(ns).Update(
            ctx,
            secret,
            metav1.UpdateOptions{},
        )
        if err != nil {
            return fmt.Errorf("failed to update secret %s/%s: %w",
                ns, secretName, err)
        }
        log.Println("✅ Secret cleanup completed ")
    } else {
        log.Println("No expired sessions found. Nothing to clean")
    }

    return nil
}