import { Button } from "@heroui/button";
import Link from "next/link";
import { FaRegSmile } from "react-icons/fa";

export default function Home() {
  return (
    <div className="text-3xl">
      <h1>Hello app!</h1>
      <Button
        as={Link}
        href="/members"
        color="primary"
        variant="bordered"
        startContent={<FaRegSmile size={20} />}
      >
        Click me
      </Button>
    </div>
  );
}
